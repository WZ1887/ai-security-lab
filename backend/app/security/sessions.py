"""登录会话与刷新令牌。

刷新令牌是随机串（不是 JWT），数据库只存 sha256 摘要：
  - 库被读走也无法直接冒用
  - 轮换：刷新时同一行换新摘要，旧令牌立即失效
  - 注销：revoked_at 置位（可审计、可批量下线）

注意：这里只做“轮换”，没有做令牌族复用检测（需要额外记录历史摘要）。
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import Session as UserSession


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return secrets.token_urlsafe(48)


def issue(
    db: Session,
    *,
    user_id: str,
    tenant_id: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[UserSession, str]:
    token = _new_token()
    now = datetime.utcnow()
    record = UserSession(
        id=str(uuid.uuid4()),
        user_id=user_id,
        tenant_id=tenant_id,
        refresh_token_hash=_digest(token),
        ip=ip,
        user_agent=(user_agent or "")[:255] or None,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record, token


def find(db: Session, token: str | None) -> UserSession | None:
    if not token:
        return None
    return (
        db.query(UserSession)
        .filter(UserSession.refresh_token_hash == _digest(token))
        .first()
    )


def is_active(record: UserSession, now: datetime | None = None) -> bool:
    now = now or datetime.utcnow()
    return record.revoked_at is None and record.expires_at > now


def rotate(db: Session, record: UserSession) -> str:
    """轮换刷新令牌：同一行换摘要，旧令牌立刻失效。"""
    token = _new_token()
    record.refresh_token_hash = _digest(token)
    record.expires_at = datetime.utcnow() + timedelta(seconds=settings.refresh_token_ttl)
    db.commit()
    return token


def revoke(db: Session, record: UserSession) -> None:
    if record.revoked_at is None:
        record.revoked_at = datetime.utcnow()
        db.commit()


def revoke_all_for_user(db: Session, user_id: str) -> int:
    count = 0
    for record in (
        db.query(UserSession)
        .filter(UserSession.user_id == user_id)
        .filter(UserSession.revoked_at.is_(None))
        .all()
    ):
        record.revoked_at = datetime.utcnow()
        count += 1
    if count:
        db.commit()
    return count
