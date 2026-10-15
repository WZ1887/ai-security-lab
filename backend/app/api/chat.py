"""聊天接口：Agent + Gateway 端到端。

流程：
  user_input
    → G1 规范化 + G2 语义风险
    → Agent 规划工具调用
    → 工具调用经 Gateway（G3-G5）
    → 返回结构化响应

会话级数据标签跟踪：
  每个 session 维护一个标签集合，工具返回的标签累积进去，
  下次工具调用时作为 data_labels_in 传入，实现多轮数据流策略。
"""

import time
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agent.planner import ToolInfo, plan
from app.mcp_guard.approval import service as approval_service
from app.mcp_guard.canonicalize.g1 import CanonicalizeInput, canonicalize
from app.mcp_guard.semantic.g2 import SemanticInput, analyze as semantic_analyze
from app.mcp_guard.gateway import GatewayRequest, PrecomputedGates, handle_tool_call
from app.mcp_guard.registry.sync import build_tool_index
from app.memory import service as memory_service
from app.models.db import get_db
from app.security.principal import Principal, get_principal

router = APIRouter(prefix="/api", tags=["chat"])


# ---------- 工具元数据：唯一来源是 MCP Server 的 ToolSpec ----------
# 见 mcp_guard/registry/sync.py。这里不再手写副本，
# 否则 planner 描述、注册表哈希、执行器三处会各自漂移。
_TOOL_INDEX: dict[str, dict] = build_tool_index()


# ---------- 会话级数据标签跟踪 ----------
_SESSION_LABELS: dict[str, set[str]] = {}


def _get_session_labels(session_id: str) -> list[str]:
    return sorted(_SESSION_LABELS.get(session_id, set()))


def _add_session_labels(session_id: str, labels: list[str]) -> None:
    if not labels:
        return
    if session_id not in _SESSION_LABELS:
        _SESSION_LABELS[session_id] = set()
    _SESSION_LABELS[session_id].update(labels)


def _reset_session(session_id: str) -> None:
    _SESSION_LABELS.pop(session_id, None)


# ---------- 工具清单（供 Agent 规划用） ----------
_TOOLS: list[ToolInfo] = [
    ToolInfo(
        name=name,
        description=meta["description"],
        input_schema=meta["input_schema"],
    )
    for name, meta in _TOOL_INDEX.items()
]


# ---------- 请求/响应模型 ----------
class ChatRequest(BaseModel):
    session_id: str = "sess_default"
    user_input: str
    reset_session: bool = False
    # G4 要求审批时，带上审批通过的令牌重发同一请求
    approval_token: str | None = None

    # 注意：user_id / tenant_id / roles / agent_id 曾经来自请求体，
    # 现在一律以认证令牌为准，请求体里带了也不会被采信。


class ChatResponse(BaseModel):
    reply: str
    blocked: bool = False
    blocked_gate: str | None = None
    blocked_reason: str | None = None

    tool_name: str | None = None
    tool_args: dict | None = None
    tool_result: Any = None

    g1: dict = Field(default_factory=dict)
    g2: dict = Field(default_factory=dict)
    g3: dict = Field(default_factory=dict)
    g4: dict = Field(default_factory=dict)
    g5: dict = Field(default_factory=dict)

    # 需要人工审批时回填，供前端展示 / 走审批流程
    approval_required: bool = False
    approval_id: str | None = None
    approval_payload: dict | None = None

    session_labels: list[str] = Field(default_factory=list)
    # 本轮注入模型的记忆事实（读侧已过滤；事实 ≠ 指令）
    memory_facts: list[str] = Field(default_factory=list)
    latency_ms: int = 0


# ---------- 辅助 ----------
def _compose_reply_success(tool_name: str, result: Any) -> str:
    # 工具返回错误（含被伪装成 not_found 的越权访问）时不要假装成功
    if isinstance(result, dict) and result.get("error"):
        return "没有找到对应的数据，或当前身份无权访问该数据。"
    if tool_name == "get_order" and isinstance(result, dict) and "order_id" in result:
        return (
            f"订单 {result.get('order_id')} 状态：{result.get('status')}，"
            f"金额 {result.get('amount')} 元。"
        )
    if tool_name == "search_knowledge" and isinstance(result, dict):
        results = result.get("results", [])
        if results:
            first = results[0]
            return f"{first.get('title')}：{first.get('content')}"
        return "知识库暂无相关结果。"
    if tool_name == "send_email" and isinstance(result, dict):
        return f"邮件已发送到 {result.get('to')}。"
    if tool_name == "transfer_funds" and isinstance(result, dict):
        return f"转账完成：{result.get('amount')} 元 → {result.get('to')}。"
    return "操作完成。"


def _compose_reply_blocked(gate: str | None, reason: str | None) -> str:
    if gate == "G3":
        return "本次操作被安全网关拦截：工具未通过信任校验。"
    if gate == "G4":
        if reason and "PII_TO_EXTERNAL" in reason:
            return "抱歉，检测到敏感个人信息可能外泄，已阻止该操作。"
        if reason and "FINANCIAL_TO_EXTERNAL" in reason:
            return "抱歉，检测到财务数据可能外泄，已阻止该操作。"
        if reason and "TOOL_NOT_IN_ROLE" in reason:
            return "抱歉，当前身份无权执行该操作。"
        if reason and "MEMORY_CANNOT_STORE_POLICY" in reason:
            return "长期记忆只能保存事实，不能保存规则或权限。这条内容没有被记住。"
        if reason and "MEMORY_CONTAINS_INSTRUCTION" in reason:
            return "这段内容看起来包含指令，已拒绝写入长期记忆。"
        if reason and ("HIGH_RISK_TOOL" in reason or "INTERNAL_TO_EXTERNAL" in reason):
            return "该操作需要人工审批，请确认后再试。"
        return "本次操作被策略引擎拒绝。"
    if gate == "G5":
        if reason and "APPROVAL_REQUIRED" in reason:
            return "该操作需要人工审批，请确认后再试。"
        if reason and "RESULT_GUARD" in reason:
            return "工具返回内容存在安全风险，已被拦截。"
        return "执行阶段被安全策略拦截。"
    return "本次请求被安全策略拦截。"


# ---------- 主接口 ----------
@router.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ChatResponse:
    start = time.perf_counter()
    agent_id = principal.agent_id or principal.user_id

    if req.reset_session:
        _reset_session(req.session_id)

    # 1. G1
    g1_out = canonicalize(CanonicalizeInput(raw_text=req.user_input, source="user"))

    # 2. G2
    g2_out = semantic_analyze(
        SemanticInput(normalized_text=g1_out.normalized_text, source="user")
    )

    resp = ChatResponse(
        reply="",
        g1={
            "transformations": g1_out.transformations,
            "risk_signals": g1_out.risk_signals,
            "expansion_ratio": g1_out.expansion_ratio,
        },
        g2={
            "risk_score": g2_out.risk_score,
            "signals": g2_out.signals,
            "action": g2_out.action,
            "benign_score": g2_out.benign_score,
            "margin": g2_out.margin,
        },
    )

    # 记忆读取：只注入经过读侧过滤的“事实”，并明确标注为不可信数据
    try:
        memory_facts, _dropped = memory_service.recall_for_prompt(
            tenant_id=principal.tenant_id,
            user_id=principal.resource_user_id,
        )
    except Exception:
        memory_facts = []
    resp.memory_facts = memory_facts

    # 3. Agent 规划
    try:
        plan_result = plan(req.user_input, _TOOLS, memory_facts=memory_facts)
    except Exception as e:
        # 规划模型不可用：显式失败，而不是抛 500 让调用方猜
        resp.blocked = True
        resp.blocked_gate = "PLANNER"
        resp.blocked_reason = f"PLANNER_UNAVAILABLE:{type(e).__name__}"
        resp.reply = "助手模型暂时不可用，请稍后再试。"
        resp.latency_ms = int((time.perf_counter() - start) * 1000)
        return resp

    if plan_result.tool_name is None:
        resp.reply = "您好，我可以帮您查订单、查知识库、发邮件或处理退款。请告诉我您的需求。"
        resp.session_labels = _get_session_labels(req.session_id)
        resp.latency_ms = int((time.perf_counter() - start) * 1000)
        return resp

    tool_name = plan_result.tool_name
    meta = _TOOL_INDEX.get(tool_name)
    if meta is None:
        resp.reply = "抱歉，暂不支持该操作。"
        resp.blocked = True
        resp.blocked_gate = "INTERNAL"
        resp.blocked_reason = f"UNKNOWN_TOOL:{tool_name}"
        resp.latency_ms = int((time.perf_counter() - start) * 1000)
        return resp

    # 4. Gateway
    gw_resp = handle_tool_call(
        db,
        GatewayRequest(
            session_id=req.session_id,
            user_id=principal.resource_user_id,
            tenant_id=principal.tenant_id,
            roles=list(principal.roles),
            agent_id=agent_id,
            delegation_scope=[],
            user_input=req.user_input,
            server_id=meta["server_id"],
            server_fingerprint=meta["server_fingerprint"],
            tool_name=tool_name,
            tool_version=meta["tool_version"],
            tool_input_schema=meta["input_schema"],
            tool_arguments=plan_result.arguments,
            tool_hashes={
                "input_schema_hash": meta["input_schema_hash"],
                "description_hash": meta["description_hash"],
                "capability_hash": meta["capability_hash"],
                "output_schema_hash": meta["output_schema_hash"],
            },
            data_labels_in=_get_session_labels(req.session_id),
            approval_token=req.approval_token,
            executor=meta["executor"],
        ),
        # G1/G2 上面已经算过，直接复用，避免同一请求重复做语义分析
        PrecomputedGates(g1=g1_out, g2=g2_out),
    )

    resp.tool_name = tool_name
    resp.tool_args = plan_result.arguments
    resp.g3 = gw_resp.g3
    resp.g4 = gw_resp.g4
    resp.g5 = gw_resp.g5

    if not gw_resp.allowed:
        resp.blocked = True
        resp.blocked_gate = gw_resp.blocked_gate
        resp.blocked_reason = gw_resp.final_reason
        resp.reply = _compose_reply_blocked(gw_resp.blocked_gate, gw_resp.final_reason)

        # G4 要求人工审批 → 落一条待审批记录，把 approval_id 交回前端。
        # 审批通过后携带 approval_token 重发同一个请求即可执行。
        if gw_resp.g4.get("approval_required"):
            payload = {
                "tool": tool_name,
                "arguments": plan_result.arguments,
                "session_id": req.session_id,
                "requested_by": agent_id,
                "policy_reason": gw_resp.final_reason,
            }
            try:
                rec = approval_service.create_pending(
                    db,
                    session_id=req.session_id,
                    tenant_id=principal.tenant_id,
                    action=tool_name,
                    requested_by=agent_id,
                    action_payload=payload,
                )
            except Exception as e:  # 审批落库失败不改变“拒绝”这个结论
                resp.blocked_reason = (
                    f"{gw_resp.final_reason}|APPROVAL_CREATE_FAILED:{type(e).__name__}"
                )
            else:
                resp.approval_required = True
                resp.approval_id = rec.approval_id
                resp.approval_payload = payload
                resp.reply = (
                    f"该操作需要人工审批（审批单 {rec.approval_id}）。"
                    "审批通过后携带 approval_token 重新发起同一请求即可执行。"
                )

        resp.session_labels = _get_session_labels(req.session_id)
        resp.latency_ms = int((time.perf_counter() - start) * 1000)
        return resp

    # 5. 成功 → 累积标签
    resp.tool_result = gw_resp.result
    resp.reply = _compose_reply_success(tool_name, gw_resp.result)
    _add_session_labels(req.session_id, gw_resp.result_labels)

    resp.session_labels = _get_session_labels(req.session_id)
    resp.latency_ms = int((time.perf_counter() - start) * 1000)
    return resp
