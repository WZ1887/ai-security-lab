"""G4 策略引擎：RBAC + ABAC + Data Flow + 风险信号合并。"""

import time
from dataclasses import dataclass, field

from app.mcp_guard.dataflow.engine import evaluate as dataflow_evaluate
from app.mcp_guard.dataflow.labels import get_sink_type
from app.mcp_guard.policy.rules import (
    HIGH_RISK_TOOLS,
    MEDIUM_RISK_TOOLS,
    role_allows_tool,
)


SEMANTIC_APPROVAL_THRESHOLD = 0.85


@dataclass
class Subject:
    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)


@dataclass
class AgentIdentity:
    agent_id: str
    delegation_scope: list[str] = field(default_factory=list)


@dataclass
class SessionInfo:
    session_id: str
    jti: str | None = None
    expires_at: int | None = None


@dataclass
class PolicyInput:
    subject: Subject
    agent: AgentIdentity
    session: SessionInfo
    tool_name: str
    tool_risk_level: str          # low / medium / high
    output_labels: list[str]
    data_labels_in: list[str]
    requested_action: str
    resource: dict = field(default_factory=dict)
    semantic_risk: float = 0.0
    semantic_action: str = "ALLOW"


@dataclass
class PolicyOutput:
    decision: str                 # ALLOW / DENY / REQUIRE_APPROVAL
    reason: str
    policy_id: str
    data_labels_out: list[str]
    approval_required: bool
    elapsed_ms: int


def _finalize(decision, reason, policy_id, labels, start):
    return PolicyOutput(
        decision=decision,
        reason=reason,
        policy_id=policy_id,
        data_labels_out=labels,
        approval_required=(decision == "REQUIRE_APPROVAL"),
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )


def evaluate(inp: PolicyInput) -> PolicyOutput:
    start = time.perf_counter()

    # ---------- 1. RBAC ----------
    if not role_allows_tool(inp.subject.roles, inp.tool_name):
        return _finalize(
            "DENY", "TOOL_NOT_IN_ROLE", "RBAC-001", [], start
        )

    # ---------- 2. 委派范围 ----------
    if inp.agent.delegation_scope:
        if inp.tool_name not in inp.agent.delegation_scope and "*" not in inp.agent.delegation_scope:
            return _finalize(
                "DENY", "TOOL_NOT_IN_DELEGATION", "RBAC-002", [], start
            )

    # ---------- 3. Data Flow ----------
    sink_type = get_sink_type(inp.tool_name)
    df = dataflow_evaluate(inp.data_labels_in, sink_type)

    if df.action == "DENY":
        return _finalize(
            "DENY", df.reason, df.rule_id, inp.output_labels, start
        )

    # ---------- 4. 风险信号合并 ----------
    force_approval = False
    reason = "OK"
    policy_id = "POL-000"

    if df.action == "REQUIRE_APPROVAL":
        force_approval = True
        reason = df.reason
        policy_id = df.rule_id

    # 高风险工具：强制审批
    if inp.tool_name in HIGH_RISK_TOOLS:
        force_approval = True
        if reason == "OK":
            reason = "HIGH_RISK_TOOL"
            policy_id = "POL-101"

    # 语义风险高 + 中高风险工具 → 审批
    if inp.semantic_risk >= SEMANTIC_APPROVAL_THRESHOLD:
        if inp.tool_risk_level in ("medium", "high") or inp.tool_name in MEDIUM_RISK_TOOLS:
            force_approval = True
            if reason == "OK":
                reason = "SEMANTIC_RISK_ELEVATED"
                policy_id = "POL-201"

    if force_approval:
        return _finalize(
            "REQUIRE_APPROVAL", reason, policy_id, inp.output_labels, start
        )

    return _finalize("ALLOW", "OK", "POL-000", inp.output_labels, start)