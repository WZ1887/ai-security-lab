"""审计接口：查询 audit_events + 安全指标。"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.mcp_guard.audit.logger import verify_chain
from app.models.audit_event import AuditEvent
from app.models.db import get_db
from app.security.principal import Principal, get_principal
from app.security.roles import AUDIT_ROLES, require_audit_role  # noqa: F401


router = APIRouter(prefix="/api/audit", tags=["audit"])


class AuditEventItem(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    tenant_id: str
    session_id: str | None
    subject: str | None
    agent: str | None
    tool_name: str | None
    policy_action: str
    policy_reason: str | None
    risk_score: float | None
    latency_ms: int | None
    gate_results: dict | None = None


class AuditListResponse(BaseModel):
    total: int
    items: list[AuditEventItem]


class AuditStats(BaseModel):
    total_events: int
    allow_count: int
    deny_count: int
    require_approval_count: int
    blocked_count: int
    block_rate: float
    p95_latency_ms: int
    top_reasons: list[dict] = Field(default_factory=list)
    top_tools: list[dict] = Field(default_factory=list)


class ChainVerifyResponse(BaseModel):
    checked: int
    valid: bool
    broken_at: dict | None = None
    chain_head: str | None = None


def _parse_gate_results(raw: str | None) -> dict | None:
    if not raw:
        return None
    import json
    try:
        return json.loads(raw)
    except Exception:
        return None


@router.get("/events", response_model=AuditListResponse)
def list_events(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = None,
    tool_name: str | None = None,
    session_id: str | None = None,
):
    # 审计按租户隔离：只能看到自己租户的事件
    q = db.query(AuditEvent).filter(AuditEvent.tenant_id == principal.tenant_id)
    if action:
        q = q.filter(AuditEvent.policy_action == action)
    if tool_name:
        q = q.filter(AuditEvent.tool_name == tool_name)
    if session_id:
        q = q.filter(AuditEvent.session_id == session_id)

    total = q.count()
    rows = q.order_by(desc(AuditEvent.id)).offset(offset).limit(limit).all()

    items = []
    for r in rows:
        items.append(
            AuditEventItem(
                id=r.id,
                event_id=r.event_id,
                timestamp=r.timestamp,
                tenant_id=r.tenant_id,
                session_id=r.session_id,
                subject=r.subject,
                agent=r.agent,
                tool_name=r.tool_name,
                policy_action=r.policy_action,
                policy_reason=r.policy_reason,
                risk_score=r.risk_score,
                latency_ms=r.latency_ms,
                gate_results=_parse_gate_results(r.gate_results),
            )
        )
    return AuditListResponse(total=total, items=items)


@router.get("/stats", response_model=AuditStats)
def stats(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    tenant_filter = AuditEvent.tenant_id == principal.tenant_id
    total = db.query(func.count(AuditEvent.id)).filter(tenant_filter).scalar() or 0

    def _count(action: str) -> int:
        return (
            db.query(func.count(AuditEvent.id))
            .filter(tenant_filter)
            .filter(AuditEvent.policy_action == action)
            .scalar()
            or 0
        )

    allow = _count("ALLOW")
    deny = _count("DENY")
    approval = _count("REQUIRE_APPROVAL")

    # 拦截率把 REQUIRE_APPROVAL 也算进来：没通过人工审批的操作并没有执行
    blocked = deny + approval
    block_rate = round((blocked / total), 4) if total > 0 else 0.0

    latencies = [
        r[0]
        for r in db.query(AuditEvent.latency_ms)
        .filter(tenant_filter)
        .filter(AuditEvent.latency_ms.isnot(None))
        .all()
    ]
    latencies.sort()
    p95 = 0
    if latencies:
        idx = max(0, int(len(latencies) * 0.95) - 1)
        p95 = latencies[idx]

    reasons = (
        db.query(AuditEvent.policy_reason, func.count(AuditEvent.id))
        .filter(tenant_filter)
        .group_by(AuditEvent.policy_reason)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
        .all()
    )
    top_reasons = [{"reason": r[0], "count": r[1]} for r in reasons if r[0]]

    tools = (
        db.query(AuditEvent.tool_name, func.count(AuditEvent.id))
        .filter(tenant_filter)
        .filter(AuditEvent.tool_name.isnot(None))
        .group_by(AuditEvent.tool_name)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
        .all()
    )
    top_tools = [{"tool": t[0], "count": t[1]} for t in tools if t[0]]

    return AuditStats(
        total_events=total,
        allow_count=allow,
        deny_count=deny,
        require_approval_count=approval,
        blocked_count=blocked,
        block_rate=block_rate,
        p95_latency_ms=p95,
        top_reasons=top_reasons,
        top_tools=top_tools,
    )


@router.get("/verify", response_model=ChainVerifyResponse)
def verify(
    principal: Principal = Depends(require_audit_role),
    db: Session = Depends(get_db),
) -> ChainVerifyResponse:
    """重算审计哈希链，返回第一个断裂点（如果没有则 valid=true）。"""
    return ChainVerifyResponse(**verify_chain(db))
