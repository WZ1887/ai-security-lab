"""审计事件写入器。

每次工具调用写一行 audit_events。
hash chain: event_hash = sha256(prev_hash + 本次关键字段)
"""

import hashlib
import json
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent


def _compute_event_hash(prev_hash: str | None, payload: dict) -> str:
    base = (prev_hash or "") + json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(base.encode("utf-8")).hexdigest()


def _last_event_hash(db: Session) -> str | None:
    last = (
        db.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    if last is None:
        return None
    return last.event_hash


def write_event(
    db: Session,
    *,
    tenant_id: str,
    session_id: str | None,
    subject: str | None,
    agent: str | None,
    server_id: str | None,
    tool_name: str | None,
    gate_results: dict,
    policy_action: str,
    policy_reason: str,
    input_hash: str | None = None,
    tool_schema_hash: str | None = None,
    result_hash: str | None = None,
    risk_score: float | None = None,
    latency_ms: int | None = None,
) -> AuditEvent:
    prev_hash = _last_event_hash(db)

    payload = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "subject": subject,
        "agent": agent,
        "server_id": server_id,
        "tool_name": tool_name,
        "policy_action": policy_action,
        "policy_reason": policy_reason,
        "risk_score": risk_score,
        "latency_ms": latency_ms,
    }
    event_hash = _compute_event_hash(prev_hash, payload)

    ev = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        tenant_id=tenant_id,
        session_id=session_id,
        subject=subject,
        agent=agent,
        server_id=server_id,
        tool_name=tool_name,
        gate_results=json.dumps(gate_results, ensure_ascii=False),
        policy_action=policy_action,
        policy_reason=policy_reason,
        input_hash=input_hash,
        tool_schema_hash=tool_schema_hash,
        result_hash=result_hash,
        risk_score=risk_score,
        latency_ms=latency_ms,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev