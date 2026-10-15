"""自注册。

两条硬规则：
  1. 自注册账号的租户与角色都是**服务端固定**的（最低权限），
     请求体里只能给 email / password —— 否则刚堵上的“自封身份”又开了一个口子。
  2. 注册响应不区分“邮箱已存在”与“注册成功”，避免拿注册接口枚举账号。

邮箱验证令牌是不透明随机串，数据库只存 sha256；dev 环境会在响应里回显令牌，
便于本机跑通流程，真实部署应改为发邮件（见 docs/implementation-status.md）。
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User
from app.security import users
from app.security.users import AuthError


# 自注册只能拿到这个角色（ROLE_TOOLS 里它没有任何工具权限）
DEFAULT_SIGNUP_ROLES = ("customer",)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_verification_token(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    user.verification_token_hash = _digest(token)
    user.verification_expires_at = datetime.utcnow() + timedelta(
        seconds=settings.verification_token_ttl_seconds
    )
    db.commit()
    return token


def register(db: Session, *, email: str, password: str) -> tuple[User, str | None]:
    """创建待验证账号。

    返回 (user, 明文验证令牌)。邮箱已存在时令牌为 None——调用方据此生成
    与成功路径一致的响应，不泄露账号是否存在。
    """
    normalized = (email or "").strip().lower()
    if not _EMAIL_RE.match(normalized):
        raise AuthError("INVALID_EMAIL")

    problem = users.validate_password(password)
    if problem:
        raise AuthError(problem)

    existing = users.get_by_email(db, normalized)
    if existing is not None:
        return existing, None

    users.ensure_tenant(db, settings.default_signup_tenant, settings.default_signup_tenant)
    user = users.create_user(
        db,
        email=normalized,
        password=password,
        tenant_id=settings.default_signup_tenant,
        roles=DEFAULT_SIGNUP_ROLES,
        status="pending",
    )
    return user, issue_verification_token(db, user)


def verify_email(db: Session, token: str) -> User:
    if not token:
        raise AuthError("INVALID_VERIFICATION_TOKEN")

    user = (
        db.query(User)
        .filter(User.verification_token_hash == _digest(token))
        .first()
    )
    if user is None:
        raise AuthError("INVALID_VERIFICATION_TOKEN")
    if user.verification_expires_at and user.verification_expires_at <= datetime.utcnow():
        raise AuthError("VERIFICATION_TOKEN_EXPIRED")

    user.email_verified_at = datetime.utcnow()
    user.verification_token_hash = None
    user.verification_expires_at = None
    if (user.status or "").lower() == "pending":
        user.status = "active"
    db.commit()
    db.refresh(user)
    return user
