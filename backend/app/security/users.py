"""用户服务：登录校验、失败锁定、角色与状态管理。"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import Tenant, User
from app.security import passwords


class AuthError(Exception):
    """认证失败，reason 是可对外返回的稳定错误码。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_roles(raw: str | None) -> tuple[str, ...]:
    return tuple(r.strip() for r in (raw or "").split(",") if r.strip())


def dump_roles(roles) -> str:
    return ",".join(sorted({str(r).strip() for r in roles if str(r).strip()}))


def get_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == (email or "").strip().lower()).first()


def get_by_id(db: Session, user_id: str) -> User | None:
    return db.query(User).filter(User.id == user_id).first()


def ensure_tenant(db: Session, tenant_id: str, name: str = "") -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        tenant = Tenant(id=tenant_id, name=name or tenant_id, status="active")
        db.add(tenant)
        db.commit()
    return tenant


def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    tenant_id: str,
    roles,
    user_id: str | None = None,
    on_behalf_of: str = "",
    status: str = "active",
) -> User:
    user = User(
        id=user_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        email=(email or "").strip().lower(),
        password_hash=passwords.hash_password(password),
        roles=dump_roles(roles),
        on_behalf_of=on_behalf_of or "",
        status=status,
        mfa_enabled=False,
        # 管理员建的号视为已验证；自注册的号要走邮箱验证
        email_verified_at=datetime.utcnow() if status == "active" else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def status_error(user: User) -> str | None:
    """账号状态是否阻止登录；None 表示正常。"""
    status = (user.status or "active").lower()
    if status == "pending":
        return "EMAIL_NOT_VERIFIED"
    if status in ("disabled", "suspended"):
        return "ACCOUNT_DISABLED"
    if status == "locked":
        return "ACCOUNT_LOCKED"
    return None


def is_locked(user: User, now: datetime | None = None) -> bool:
    """是否处于“连续失败锁定”窗口内（到期自动解除）。"""
    now = now or datetime.utcnow()
    return bool(user.locked_until and user.locked_until > now)


def validate_password(password: str) -> str | None:
    """最简口令策略：长度 + 字母 + 数字。返回错误码或 None。"""
    if len(password or "") < settings.password_min_length:
        return "PASSWORD_TOO_SHORT"
    if not any(c.isalpha() for c in password):
        return "PASSWORD_NEEDS_LETTER"
    if not any(c.isdigit() for c in password):
        return "PASSWORD_NEEDS_DIGIT"
    return None


def register_failure(db: Session, user: User) -> None:
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= settings.login_max_failed_attempts:
        user.locked_until = datetime.utcnow() + timedelta(
            seconds=settings.login_lockout_seconds
        )
        user.failed_attempts = 0
    db.commit()


def reset_failures(db: Session, user: User) -> None:
    if user.failed_attempts or user.locked_until:
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()


def authenticate(
    db: Session,
    *,
    email: str,
    password: str,
    totp_code: str | None = None,
) -> User:
    """校验口令（+ 可选的 TOTP），成功返回 User。

    失败一律抛 INVALID_CREDENTIALS（不区分“用户不存在 / 密码错误”），
    但账号锁定状态是明确回报的，否则用户无法自助排查。
    """
    user = get_by_email(db, email)
    if user is None:
        # 保持一次哈希计算，避免用响应时间探测账号是否存在
        passwords.verify_password(password, "$2b$12$" + "x" * 53)
        raise AuthError("INVALID_CREDENTIALS")

    error = status_error(user)
    if error:
        raise AuthError(error)

    if is_locked(user):
        raise AuthError("ACCOUNT_LOCKED")

    if not passwords.verify_password(password, user.password_hash):
        register_failure(db, user)
        raise AuthError("INVALID_CREDENTIALS")

    if user.mfa_enabled:
        from app.security import totp

        if not totp.verify(totp_code or "", user.mfa_secret or ""):
            register_failure(db, user)
            raise AuthError("MFA_REQUIRED")

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)

    reset_failures(db, user)
    return user


def set_roles(db: Session, user: User, roles) -> User:
    user.roles = dump_roles(roles)
    db.commit()
    db.refresh(user)
    return user


def set_status(db: Session, user: User, status: str) -> User:
    user.status = status
    db.commit()
    db.refresh(user)
    return user


def set_scope(db: Session, user: User, on_behalf_of: str) -> User:
    """绑定/解绑代理的客户（由管理员操作）。"""
    user.on_behalf_of = (on_behalf_of or "").strip()
    db.commit()
    db.refresh(user)
    return user


def adopt_into_tenant(
    db: Session,
    user: User,
    *,
    tenant_id: str,
    roles,
    on_behalf_of: str = "",
) -> User:
    """把自注册账号纳入某个租户并赋角色（自助注册 → 被邀请）。

    调用方必须先确认该账号仍属于公共租户，否则就成了跨租户提权。
    """
    ensure_tenant(db, tenant_id, tenant_id)
    user.tenant_id = tenant_id
    user.roles = dump_roles(roles)
    user.on_behalf_of = (on_behalf_of or "").strip()
    db.commit()
    db.refresh(user)
    return user


def list_users(
    db: Session,
    *,
    tenant_id: str | None = None,
    limit: int = 100,
) -> list[User]:
    q = db.query(User)
    if tenant_id:
        q = q.filter(User.tenant_id == tenant_id)
    return q.order_by(User.created_at.desc()).limit(limit).all()


def change_password(
    db: Session,
    user: User,
    *,
    current_password: str,
    new_password: str,
) -> None:
    """改密。调用方负责撤销既有会话/刷新令牌。"""
    if not passwords.verify_password(current_password, user.password_hash):
        raise AuthError("INVALID_CREDENTIALS")
    problem = validate_password(new_password)
    if problem:
        raise AuthError(problem)
    if passwords.verify_password(new_password, user.password_hash):
        raise AuthError("PASSWORD_UNCHANGED")
    user.password_hash = passwords.hash_password(new_password)
    db.commit()


# 仅 dev 环境使用的演示账号（口令统一为 Demo1234!）
DEMO_PASSWORD = "Demo1234!"
DEMO_USERS = [
    {
        "email": "cs01@example.com",
        "user_id": "u_cs_01",
        "tenant_id": "tenant_001",
        "roles": ["cs_agent"],
        "on_behalf_of": "user_001",     # 客服代客户 user_001 操作
    },
    {
        "email": "finance01@example.com",
        "user_id": "u_finance_01",
        "tenant_id": "tenant_001",
        "roles": ["finance_agent"],
        "on_behalf_of": "",
    },
    {
        "email": "manager01@example.com",
        "user_id": "u_manager_01",
        "tenant_id": "tenant_001",
        "roles": ["admin", "finance_manager", "auditor"],
        "on_behalf_of": "",
    },
    {
        # 另一个租户的客服：用来演示跨租户 / 跨用户读单被拦
        "email": "cs02@example.com",
        "user_id": "u_cs_02",
        "tenant_id": "tenant_002",
        "roles": ["cs_agent"],
        "on_behalf_of": "user_002",
    },
]


def seed_demo_users(db: Session) -> int:
    """仅 dev 环境：补齐演示账号，已存在则跳过。"""
    created = 0
    for spec in DEMO_USERS:
        if get_by_email(db, spec["email"]) is not None:
            continue
        ensure_tenant(db, spec["tenant_id"], spec["tenant_id"])
        create_user(
            db,
            email=spec["email"],
            password=DEMO_PASSWORD,
            tenant_id=spec["tenant_id"],
            roles=spec["roles"],
            user_id=spec["user_id"],
            on_behalf_of=spec["on_behalf_of"],
        )
        created += 1
    return created
