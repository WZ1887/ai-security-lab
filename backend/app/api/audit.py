"""审计接口：查询 audit_events + 安全指标。"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.db import get_db


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
    block_rate: float
    p95_latency_ms: int
    top_reasons: list[dict] = Field(default_factory=list)
    top_tools: list[dict] = Field(default_factory=list)


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
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = None,
    tool_name: str | None = None,
    session_id: str | None = None,
):
    q = db.query(AuditEvent)
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
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(AuditEvent.id)).scalar() or 0

    def _count(action: str) -> int:
        return (
            db.query(func.count(AuditEvent.id))
            .filter(AuditEvent.policy_action == action)
            .scalar()
            or 0
        )

    allow = _count("ALLOW")
    deny = _count("DENY")
    approval = _count("REQUIRE_APPROVAL")

    block_rate = round((deny / total), 4) if total > 0 else 0.0

    latencies = [
        r[0] for r in db.query(AuditEvent.latency_ms).filter(AuditEvent.latency_ms.isnot(None)).all()
    ]
    latencies.sort()
    p95 = 0
    if latencies:
        idx = max(0, int(len(latencies) * 0.95) - 1)
        p95 = latencies[idx]

    reasons = (
        db.query(AuditEvent.policy_reason, func.count(AuditEvent.id))
        .group_by(AuditEvent.policy_reason)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
        .all()
    )
    top_reasons = [{"reason": r[0], "count": r[1]} for r in reasons if r[0]]

    tools = (
        db.query(AuditEvent.tool_name, func.count(AuditEvent.id))
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
        block_rate=block_rate,
        p95_latency_ms=p95,
        top_reasons=top_reasons,
        top_tools=top_tools,
    )