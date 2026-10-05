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
from app.mcp_guard.canonicalize.g1 import CanonicalizeInput, canonicalize
from app.mcp_guard.semantic.g2 import SemanticInput, analyze as semantic_analyze
from app.mcp_guard.registry.g3 import compute_hash
from app.mcp_guard.gateway import GatewayRequest, handle_tool_call
from app.models.db import get_db

from app.mcp_servers.order_server import OrderServer
from app.mcp_servers.kb_server import KnowledgeServer
from app.mcp_servers.email_server import EmailServer
from app.mcp_servers.finance_server import FinanceServer


router = APIRouter(prefix="/api", tags=["chat"])


# ---------- 单例 Server ----------
_order = OrderServer()
_kb = KnowledgeServer()
_email = EmailServer()
_finance = FinanceServer()


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
_TOOLS = [
    ToolInfo(
        name="get_order",
        description="Get order details by order id",
        input_schema={"order_id": "str"},
    ),
    ToolInfo(
        name="search_knowledge",
        description="Search knowledge base",
        input_schema={"query": "str"},
    ),
    ToolInfo(
        name="send_email",
        description="Send email to a recipient",
        input_schema={"to": "str", "subject": "str", "body": "str"},
    ),
    ToolInfo(
        name="transfer_funds",
        description="Transfer funds between accounts",
        input_schema={"to": "str", "amount": "float"},
    ),
]


# ---------- 工具元数据（与 seed.py 严格一致） ----------
_TOOL_META: dict[str, dict] = {
    "get_order": {
        "server_id": "order-server",
        "description_hash": compute_hash("Get order details by order id"),
        "input_schema_hash": compute_hash({"order_id": "str"}),
        "capability_hash": compute_hash("read:order"),
        "executor": _order.call_tool,
    },
    "search_knowledge": {
        "server_id": "kb-server",
        "description_hash": compute_hash("Search knowledge base"),
        "input_schema_hash": compute_hash({"query": "str"}),
        "capability_hash": compute_hash("read:kb"),
        "executor": _kb.call_tool,
    },
    "send_email": {
        "server_id": "email-server",
        "description_hash": compute_hash("Send email to a recipient"),
        "input_schema_hash": compute_hash({"to": "str", "subject": "str", "body": "str"}),
        "capability_hash": compute_hash("write:email:external"),
        "executor": _email.call_tool,
    },
    "transfer_funds": {
        "server_id": "finance-server",
        "description_hash": compute_hash("Transfer funds between accounts"),
        "input_schema_hash": compute_hash({"to": "str", "amount": "float"}),
        "capability_hash": compute_hash("write:funds"),
        "executor": _finance.call_tool,
    },
}


# ---------- 请求/响应模型 ----------
class ChatRequest(BaseModel):
    session_id: str = "sess_default"
    user_id: str = "user_001"
    tenant_id: str = "tenant_001"
    roles: list[str] = Field(default_factory=lambda: ["cs_agent"])
    agent_id: str = "cs_agent_01"
    user_input: str
    reset_session: bool = False


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

    session_labels: list[str] = Field(default_factory=list)
    latency_ms: int = 0


# ---------- 辅助 ----------
def _compose_reply_success(tool_name: str, result: Any) -> str:
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
def chat(req: ChatRequest, db: Session = Depends(get_db)) -> ChatResponse:
    start = time.perf_counter()

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
        },
        g2={
            "risk_score": g2_out.risk_score,
            "signals": g2_out.signals,
            "action": g2_out.action,
            "benign_score": g2_out.benign_score,
            "margin": g2_out.margin,
        },
    )

    # 3. Agent 规划
    plan_result = plan(req.user_input, _TOOLS)

    if plan_result.tool_name is None:
        resp.reply = "您好，我可以帮您查订单、查知识库、发邮件或处理退款。请告诉我您的需求。"
        resp.session_labels = _get_session_labels(req.session_id)
        resp.latency_ms = int((time.perf_counter() - start) * 1000)
        return resp

    tool_name = plan_result.tool_name
    meta = _TOOL_META.get(tool_name)
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
            user_id=req.user_id,
            tenant_id=req.tenant_id,
            roles=req.roles,
            agent_id=req.agent_id,
            delegation_scope=[],
            user_input=req.user_input,
            server_id=meta["server_id"],
            tool_name=tool_name,
            tool_version="1.0.0",
            tool_arguments=plan_result.arguments,
            tool_hashes={
                "input_schema_hash": meta["input_schema_hash"],
                "description_hash": meta["description_hash"],
                "capability_hash": meta["capability_hash"],
            },
            data_labels_in=_get_session_labels(req.session_id),
            approval_token=None,
            executor=meta["executor"],
        ),
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