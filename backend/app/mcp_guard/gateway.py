"""MCP-Guard Gateway：串联 G1-G5 + 审计落库。

对外只暴露一个入口：handle_tool_call。
内部按顺序执行五层安全 Gate，任一层失败即终止并返回审计。
每次调用写 audit_events 表。
"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from sqlalchemy.orm import Session

from app.mcp_guard.canonicalize.g1 import (
    CanonicalizeInput,
    canonicalize,
)
from app.mcp_guard.semantic.g2 import (
    SemanticInput,
    analyze as semantic_analyze,
)
from app.mcp_guard.registry.g3 import (
    ToolCallInput,
    validate as tool_validate,
)
from app.mcp_guard.g4 import (
    AgentIdentity,
    PolicyInput,
    SessionInfo,
    Subject,
    evaluate as policy_evaluate,
)
from app.mcp_guard.g5 import (
    ExecutionInput,
    run as execution_run,
)
from app.mcp_guard.audit.logger import write_event as audit_write


@dataclass
class GatewayRequest:
    # 身份上下文
    session_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    roles: list[str] = field(default_factory=list)
    agent_id: str = ""
    delegation_scope: list[str] = field(default_factory=list)

    # 用户输入（原始）
    user_input: str = ""

    # 工具调用意图
    server_id: str = ""
    tool_name: str = ""
    tool_version: str = ""
    tool_arguments: dict = field(default_factory=dict)
    tool_hashes: dict = field(default_factory=dict)

    # 已有数据标签（来自上一次工具返回）
    data_labels_in: list[str] = field(default_factory=list)

    # 审批令牌（可选）
    approval_token: str | None = None

    # 执行器（真实调用工具）
    executor: Callable[[str, dict], dict] | None = None


@dataclass
class GatewayResponse:
    allowed: bool
    decision: str                 # ALLOW / DENY / REQUIRE_APPROVAL
    final_reason: str
    blocked_gate: str | None = None

    # 各 Gate 输出
    g1: dict = field(default_factory=dict)
    g2: dict = field(default_factory=dict)
    g3: dict = field(default_factory=dict)
    g4: dict = field(default_factory=dict)
    g5: dict = field(default_factory=dict)

    # 结果
    result: dict = field(default_factory=dict)
    result_labels: list[str] = field(default_factory=list)

    # 审计
    event_id: str = ""
    audit_id: int | None = None
    latency_ms: int = 0


def _sha256(obj) -> str:
    if isinstance(obj, str):
        data = obj.encode("utf-8")
    else:
        import json
        data = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _finalize(
    db: Session,
    req: GatewayRequest,
    resp: GatewayResponse,
    start: float,
) -> GatewayResponse:
    resp.latency_ms = int((time.perf_counter() - start) * 1000)

    if resp.decision == "PENDING":
        resp.decision = "DENY"
    resp.allowed = resp.decision == "ALLOW"

    gate_results = {
        "g1": resp.g1,
        "g2": resp.g2,
        "g3": resp.g3,
        "g4": resp.g4,
        "g5": resp.g5,
    }

    try:
        ev = audit_write(
            db,
            tenant_id=req.tenant_id or "unknown",
            session_id=req.session_id or None,
            subject=req.user_id or None,
            agent=req.agent_id or None,
            server_id=req.server_id or None,
            tool_name=req.tool_name or None,
            gate_results=gate_results,
            policy_action=resp.decision,
            policy_reason=resp.final_reason,
            input_hash=_sha256(req.user_input) if req.user_input else None,
            tool_schema_hash=req.tool_hashes.get("input_schema_hash"),
            result_hash=_sha256(resp.result) if resp.result else None,
            risk_score=resp.g2.get("risk_score"),
            latency_ms=resp.latency_ms,
        )
        resp.audit_id = ev.id
    except Exception as e:
        print(f"[audit] write failed: {type(e).__name__}: {e}")

    return resp


def handle_tool_call(db: Session, req: GatewayRequest) -> GatewayResponse:
    start = time.perf_counter()

    resp = GatewayResponse(
        allowed=False,
        decision="PENDING",
        final_reason="PENDING",
        event_id=str(uuid.uuid4()),
    )

    # ---------- G1 Canonicalization ----------
    g1_out = canonicalize(CanonicalizeInput(raw_text=req.user_input, source="user"))
    resp.g1 = {
        "transformations": g1_out.transformations,
        "risk_signals": g1_out.risk_signals,
        "truncated": g1_out.truncated,
        "elapsed_ms": g1_out.elapsed_ms,
    }

    if "high_expansion_ratio" in g1_out.risk_signals:
        resp.decision = "DENY"
        resp.final_reason = "G1_HIGH_EXPANSION"
        resp.blocked_gate = "G1"
        return _finalize(db, req, resp, start)

    # ---------- G2 Semantic Risk ----------
    g2_out = semantic_analyze(
        SemanticInput(
            normalized_text=g1_out.normalized_text,
            source="user",
            context_window=[],
        )
    )
    resp.g2 = {
        "risk_score": g2_out.risk_score,
        "signals": g2_out.signals,
        "action": g2_out.action,
        "benign_score": g2_out.benign_score,
        "margin": g2_out.margin,
        "elapsed_ms": g2_out.elapsed_ms,
    }

    # ---------- 无工具调用 → 只做 G1+G2 ----------
    if not req.tool_name:
        resp.decision = "ALLOW"
        resp.final_reason = "NO_TOOL_CALL"
        return _finalize(db, req, resp, start)

    # ---------- G3 Tool Trust ----------
    g3_out = tool_validate(
        db,
        ToolCallInput(
            server_id=req.server_id,
            tool_name=req.tool_name,
            tool_version=req.tool_version,
            input_schema_hash=req.tool_hashes.get("input_schema_hash", ""),
            description_hash=req.tool_hashes.get("description_hash", ""),
            capability_hash=req.tool_hashes.get("capability_hash", ""),
            arguments=req.tool_arguments,
            session_token=None,
        ),
    )
    resp.g3 = {
        "valid": g3_out.valid,
        "reason": g3_out.reason,
        "risk_level": g3_out.tool_risk_level,
        "output_labels": g3_out.output_labels,
        "elapsed_ms": g3_out.elapsed_ms,
    }

    if not g3_out.valid:
        resp.decision = "DENY"
        resp.final_reason = f"G3_{g3_out.reason}"
        resp.blocked_gate = "G3"
        return _finalize(db, req, resp, start)

    # ---------- G4 Policy + Data Flow ----------
    g4_out = policy_evaluate(
        PolicyInput(
            subject=Subject(
                user_id=req.user_id,
                tenant_id=req.tenant_id,
                roles=req.roles,
            ),
            agent=AgentIdentity(
                agent_id=req.agent_id,
                delegation_scope=req.delegation_scope,
            ),
            session=SessionInfo(session_id=req.session_id),
            tool_name=req.tool_name,
            tool_risk_level=g3_out.tool_risk_level,
            output_labels=g3_out.output_labels,
            data_labels_in=req.data_labels_in,
            requested_action="CALL",
            semantic_risk=g2_out.risk_score,
            semantic_action=g2_out.action,
        )
    )
    resp.g4 = {
        "decision": g4_out.decision,
        "reason": g4_out.reason,
        "policy_id": g4_out.policy_id,
        "data_labels_out": g4_out.data_labels_out,
        "approval_required": g4_out.approval_required,
        "elapsed_ms": g4_out.elapsed_ms,
    }

    if g4_out.decision == "DENY":
        resp.decision = "DENY"
        resp.final_reason = f"G4_{g4_out.reason}"
        resp.blocked_gate = "G4"
        return _finalize(db, req, resp, start)

    # ---------- G5 Approval + Execution + Result ----------
    g5_out = execution_run(
        ExecutionInput(
            session_id=req.session_id,
            tool_name=req.tool_name,
            tool_arguments=req.tool_arguments,
            requested_by=req.agent_id,
            policy_decision=g4_out.decision,
            policy_reason=g4_out.reason,
            approval_token=req.approval_token,
            executor=req.executor,
        )
    )
    resp.g5 = {
        "success": g5_out.success,
        "reason": g5_out.reason,
        "result_labels": g5_out.result_labels,
        "result_risk": g5_out.result_risk,
        "approval_verified": g5_out.approval_verified,
        "elapsed_ms": g5_out.elapsed_ms,
    }

    if not g5_out.success:
        resp.decision = "DENY"
        resp.final_reason = f"G5_{g5_out.reason}"
        resp.blocked_gate = "G5"
        return _finalize(db, req, resp, start)

    resp.decision = "ALLOW"
    resp.final_reason = "OK"
    resp.result = g5_out.result
    resp.result_labels = g5_out.result_labels
    return _finalize(db, req, resp, start)