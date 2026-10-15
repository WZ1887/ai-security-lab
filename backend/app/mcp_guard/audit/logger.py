"""审计事件写入器。

每次工具调用写一行 audit_events。
hash chain: event_hash = sha256(prev_hash + 本次关键字段)

并发说明：读上一条 → 计算 → 落库必须在同一把锁内完成（见 _chain_lock），
否则并发请求会读到同一个 prev_hash，链就分叉了。
多进程 / 多实例部署时需要改成数据库层串行化（行锁或独立序号列）。
"""

import hashlib
import json
import threading
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent


# 进程内串行化写链；多 worker 部署时需换成数据库层串行化
_chain_lock = threading.Lock()


def _compute_event_hash(prev_hash: str | None, payload: dict) -> str:
    base = (prev_hash or "") + json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(base.encode("utf-8")).hexdigest()


def _chain_payload(
    *,
    tenant_id: str,
    session_id: str | None,
    subject: str | None,
    agent: str | None,
    server_id: str | None,
    tool_name: str | None,
    policy_action: str,
    policy_reason: str | None,
    risk_score: float | None,
    latency_ms: int | None,
) -> dict:
    """参与哈希链的字段。

    写入与校验必须用同一个函数构造，否则链校验会一直报断裂。
    """
    return {
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


def _payload_from_event(ev: AuditEvent) -> dict:
    return _chain_payload(
        tenant_id=ev.tenant_id,
        session_id=ev.session_id,
        subject=ev.subject,
        agent=ev.agent,
        server_id=ev.server_id,
        tool_name=ev.tool_name,
        policy_action=ev.policy_action,
        policy_reason=ev.policy_reason,
        risk_score=ev.risk_score,
        latency_ms=ev.latency_ms,
    )


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
    payload = _chain_payload(
        tenant_id=tenant_id,
        session_id=session_id,
        subject=subject,
        agent=agent,
        server_id=server_id,
        tool_name=tool_name,
        policy_action=policy_action,
        policy_reason=policy_reason,
        risk_score=risk_score,
        latency_ms=latency_ms,
    )

    with _chain_lock:
        prev_hash = _last_event_hash(db)
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


def verify_chain(db: Session, tenant_id: str | None = None) -> dict:
    """重算哈希链，返回第一个断裂点。

    按租户过滤时只校验事件内容本身（prev_hash 指向的是全局上一条，
    跨租户不成链，链接关系无法在该视图下校验）。
    """
    q = db.query(AuditEvent).order_by(AuditEvent.id.asc())
    if tenant_id:
        q = q.filter(AuditEvent.tenant_id == tenant_id)

    prev_hash: str | None = None
    checked = 0
    for ev in q.all():
        expected = _compute_event_hash(ev.prev_hash, _payload_from_event(ev))
        if ev.event_hash != expected:
            return {
                "checked": checked,
                "valid": False,
                "broken_at": {
                    "id": ev.id,
                    "event_id": ev.event_id,
                    "reason": "EVENT_HASH_MISMATCH",
                },
                "chain_head": prev_hash,
            }
        if not tenant_id and prev_hash is not None and ev.prev_hash != prev_hash:
            return {
                "checked": checked,
                "valid": False,
                "broken_at": {
                    "id": ev.id,
                    "event_id": ev.event_id,
                    "reason": "PREV_HASH_MISMATCH",
                },
                "chain_head": prev_hash,
            }
        prev_hash = ev.event_hash
        checked += 1

    return {
        "checked": checked,
        "valid": True,
        "broken_at": None,
        "chain_head": prev_hash,
    }
