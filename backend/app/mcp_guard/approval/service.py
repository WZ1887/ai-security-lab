"""审批服务：approvals 表的读写 + 令牌签发。

G4 对高风险 / 数据流受限的操作返回 REQUIRE_APPROVAL，
这里负责把它落成一条待审批记录，并在人工批准后签发一次性令牌。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.mcp_guard.approval import tokens
from app.models.approval import Approval


class ApprovalError(Exception):
    """审批操作失败，reason 是可对外展示的错误码。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def create_pending(
    db: Session,
    *,
    session_id: str,
    tenant_id: str,
    action: str,
    requested_by: str,
    action_payload: dict,
) -> Approval:
    """创建一条 pending 审批记录。"""
    rec = Approval(
        approval_id=str(uuid.uuid4()),
        session_id=session_id or "unknown",
        tenant_id=tenant_id or "unknown",
        requested_by=requested_by or "unknown",
        action=action,
        action_payload=json.dumps(action_payload, ensure_ascii=False, sort_keys=True),
        status="pending",
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def get(db: Session, approval_id: str) -> Approval | None:
    return db.query(Approval).filter(Approval.approval_id == approval_id).first()


def list_recent(
    db: Session,
    limit: int = 50,
    tenant_id: str | None = None,
) -> list[Approval]:
    q = db.query(Approval)
    if tenant_id:
        q = q.filter(Approval.tenant_id == tenant_id)
    return q.order_by(Approval.id.desc()).limit(limit).all()


def approve(
    db: Session,
    *,
    approval_id: str,
    approver_id: str,
    ttl_seconds: int | None = None,
) -> tuple[Approval, str]:
    """批准一条 pending 记录并签发令牌，返回 (记录, token)。

    审批人必须 ≠ 发起人（防自批）；令牌与会话、工具名、发起人绑定。
    """
    rec = get(db, approval_id)
    if rec is None:
        raise ApprovalError("NOT_FOUND")
    if rec.status != "pending":
        raise ApprovalError(f"ALREADY_{rec.status.upper()}")
    if not approver_id:
        raise ApprovalError("MISSING_APPROVER")
    if approver_id == rec.requested_by:
        raise ApprovalError("SELF_APPROVAL_FORBIDDEN")

    ttl = ttl_seconds or settings.approval_token_ttl_seconds
    token = tokens.issue(
        approval_id=rec.approval_id,
        session_id=rec.session_id,
        action=rec.action,
        requested_by=rec.requested_by,
        approver_id=approver_id,
        ttl_seconds=ttl,
    )
    payload = tokens.decode_payload(token)

    rec.status = "approved"
    rec.approver_id = approver_id
    rec.approved_at = datetime.utcnow()
    rec.approval_token_jti = payload["jti"]
    rec.token_expires_at = datetime.utcfromtimestamp(payload["expires_at"])
    db.commit()
    db.refresh(rec)
    return rec, token


def reject(db: Session, *, approval_id: str, approver_id: str) -> Approval:
    """拒绝一条 pending 记录。"""
    rec = get(db, approval_id)
    if rec is None:
        raise ApprovalError("NOT_FOUND")
    if rec.status != "pending":
        raise ApprovalError(f"ALREADY_{rec.status.upper()}")

    rec.status = "rejected"
    rec.approver_id = approver_id or None
    rec.approved_at = datetime.utcnow()
    db.commit()
    db.refresh(rec)
    return rec
