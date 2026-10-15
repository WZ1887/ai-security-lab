"""认证接口。

身份的第一来源是登录：口令（bcrypt）→ 可选 TOTP → 短生命周期访问令牌 +
可轮换的刷新令牌（数据库只存摘要）。

`/dev-token` 仍然保留，但默认关闭（`ALLOW_DEV_TOKEN`）且只在 app_env=dev 可用：
它只是本机调试后门，不是身份来源。
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.models.db import get_db
from app.models.user import Session as UserSession
from app.security import ratelimit, registration
from app.security import sessions as session_service
from app.security import totp, users
from app.security.principal import Principal, get_principal, issue_access_token
from app.security.roles import require_admin_role
from app.security.users import AuthError


router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    principal: dict


class PrincipalResponse(BaseModel):
    user_id: str
    tenant_id: str
    roles: list[str]
    agent_id: str
    on_behalf_of: str
    resource_user_id: str


class DevTokenRequest(BaseModel):
    user_id: str
    tenant_id: str = "tenant_001"
    roles: list[str] = Field(default_factory=lambda: ["cs_agent"])
    agent_id: str = ""
    on_behalf_of: str = ""
    ttl_seconds: int | None = None


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaActivateRequest(BaseModel):
    totp_code: str


class StatusResponse(BaseModel):
    status: str = "ok"
    detail: str = ""


class RegisterRequest(BaseModel):
    email: str
    password: str


class ResendVerificationRequest(BaseModel):
    email: str


class VerifyEmailRequest(BaseModel):
    token: str


class RegisterResponse(BaseModel):
    status: str
    detail: str = ""
    # 仅 dev 环境回显，方便本机跑通；真实部署应改为发邮件
    verification_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AdminUserItem(BaseModel):
    user_id: str
    email: str
    tenant_id: str
    roles: list[str]
    on_behalf_of: str
    status: str
    mfa_enabled: bool
    email_verified: bool


class AdminCreateUserRequest(BaseModel):
    email: str
    password: str
    tenant_id: str
    roles: list[str] = Field(default_factory=list)
    on_behalf_of: str = ""


class SetRolesRequest(BaseModel):
    roles: list[str]


class SetStatusRequest(BaseModel):
    status: str


class SetScopeRequest(BaseModel):
    on_behalf_of: str = ""


class AdoptUserRequest(BaseModel):
    roles: list[str] = Field(default_factory=list)
    on_behalf_of: str = ""


def _principal_payload(principal: Principal) -> dict:
    return {
        "user_id": principal.user_id,
        "tenant_id": principal.tenant_id,
        "roles": list(principal.roles),
        "agent_id": principal.agent_id,
        "on_behalf_of": principal.on_behalf_of,
        "resource_user_id": principal.resource_user_id,
    }


def _tokens_for(
    db: Session,
    user,
    *,
    request: Request | None = None,
    rotate: UserSession | None = None,
) -> TokenResponse:
    """签发访问令牌 + 刷新令牌（rotate 不为空时走轮换而不是新建会话）。"""
    principal = Principal(
        user_id=user.id,
        tenant_id=user.tenant_id,
        roles=users.parse_roles(user.roles),
        agent_id=user.id,
        on_behalf_of=user.on_behalf_of or "",
    )
    access_token, claims = issue_access_token(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        roles=list(principal.roles),
        agent_id=principal.agent_id,
        on_behalf_of=principal.on_behalf_of,
    )

    if rotate is not None:
        refresh_token = session_service.rotate(db, rotate)
    else:
        _, refresh_token = session_service.issue(
            db,
            user_id=user.id,
            tenant_id=user.tenant_id,
            ip=request.client.host if request is not None and request.client else None,
            user_agent=request.headers.get("user-agent") if request is not None else None,
        )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=claims["exp"] - claims["iat"],
        principal=_principal_payload(principal),
    )


@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        user = users.authenticate(
            db,
            email=req.email,
            password=req.password,
            totp_code=req.totp_code,
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.reason) from e
    return _tokens_for(db, user, request=request)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    req: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    record = session_service.find(db, req.refresh_token)
    if record is None or not session_service.is_active(record):
        raise HTTPException(status_code=401, detail="INVALID_REFRESH_TOKEN")

    user = users.get_by_id(db, record.user_id)
    if user is None or (user.status or "active") != "active":
        session_service.revoke(db, record)
        raise HTTPException(status_code=401, detail="ACCOUNT_DISABLED")

    return _tokens_for(db, user, request=request, rotate=record)


@router.post("/logout", response_model=StatusResponse)
def logout(req: LogoutRequest, db: Session = Depends(get_db)) -> StatusResponse:
    """注销当前刷新令牌（幂等：不回显令牌是否存在）。"""
    record = session_service.find(db, req.refresh_token)
    if record is not None:
        session_service.revoke(db, record)
    return StatusResponse()


@router.get("/me", response_model=PrincipalResponse)
def me(principal: Principal = Depends(get_principal)) -> PrincipalResponse:
    return PrincipalResponse(**_principal_payload(principal))


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def mfa_enroll(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> MfaEnrollResponse:
    """生成 TOTP 密钥（此时还没开启，需要再用验证码激活）。"""
    user = users.get_by_id(db, principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    secret = totp.generate_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    db.commit()
    return MfaEnrollResponse(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(secret, user.email, settings.mfa_issuer),
    )


@router.post("/mfa/activate", response_model=StatusResponse)
def mfa_activate(
    req: MfaActivateRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> StatusResponse:
    user = users.get_by_id(db, principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA_NOT_ENROLLED")
    if not totp.verify(req.totp_code, user.mfa_secret):
        raise HTTPException(status_code=400, detail="MFA_CODE_INVALID")

    user.mfa_enabled = True
    db.commit()
    return StatusResponse(detail="MFA_ENABLED")


# ---------- 自注册（只能拿到最低权限） ----------

def _generic_registration_response(token: str | None) -> RegisterResponse:
    """成功与“邮箱已存在”返回同样的内容，避免拿注册接口枚举账号。"""
    return RegisterResponse(
        status="pending_verification",
        detail="如果邮箱可用，验证信息已发出",
        verification_token=token if settings.app_env == "dev" else None,
    )


@router.post("/register", response_model=RegisterResponse, status_code=202)
def register(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    if not settings.allow_self_registration:
        raise HTTPException(status_code=403, detail="SELF_REGISTRATION_DISABLED")

    ip = request.client.host if request.client else "unknown"
    if not ratelimit.hit(
        f"register:{ip}",
        settings.register_rate_limit_max,
        settings.register_rate_limit_window_seconds,
    ):
        raise HTTPException(status_code=429, detail="TOO_MANY_REGISTRATIONS")

    try:
        user, token = registration.register(db, email=req.email, password=req.password)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=e.reason) from e

    if token and settings.app_env == "dev":
        # 真实部署在这里发验证邮件；dev 环境直接打日志 + 回显
        print(f"[auth] 邮箱验证令牌（dev）：{user.email} -> {token}")
    return _generic_registration_response(token)


@router.post("/verify-email", response_model=TokenResponse)
def verify_email(
    req: VerifyEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        user = registration.verify_email(db, req.token)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=e.reason) from e
    return _tokens_for(db, user, request=request)


@router.post("/resend-verification", response_model=RegisterResponse)
def resend_verification(
    req: ResendVerificationRequest,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    user = users.get_by_email(db, req.email)
    if user is None or (user.status or "").lower() != "pending":
        return _generic_registration_response(None)

    token = registration.issue_verification_token(db, user)
    if settings.app_env == "dev":
        print(f"[auth] 重发邮箱验证令牌（dev）：{user.email} -> {token}")
    return _generic_registration_response(token)


# ---------- 口令 ----------

@router.post("/password", response_model=StatusResponse)
def change_password(
    req: ChangePasswordRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> StatusResponse:
    user = users.get_by_id(db, principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    try:
        users.change_password(
            db,
            user,
            current_password=req.current_password,
            new_password=req.new_password,
        )
    except AuthError as e:
        raise HTTPException(status_code=400, detail=e.reason) from e

    revoked = session_service.revoke_all_for_user(db, user.id)
    return StatusResponse(detail=f"PASSWORD_CHANGED;sessions_revoked={revoked}")


# ---------- 用户与角色管理（仅管理员，且只能管自己租户） ----------

def _user_item(user) -> AdminUserItem:
    return AdminUserItem(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        roles=list(users.parse_roles(user.roles)),
        on_behalf_of=user.on_behalf_of or "",
        status=user.status or "active",
        mfa_enabled=bool(user.mfa_enabled),
        email_verified=user.email_verified_at is not None,
    )


def _load_tenant_user(db: Session, user_id: str, principal: Principal):
    user = users.get_by_id(db, user_id)
    if user is None or user.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    return user


@router.get("/users", response_model=list[AdminUserItem])
def list_users(
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> list[AdminUserItem]:
    return [_user_item(u) for u in users.list_users(db, tenant_id=principal.tenant_id)]


@router.post("/users", response_model=AdminUserItem, status_code=201)
def create_user(
    req: AdminCreateUserRequest,
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> AdminUserItem:
    # 只能在自己租户内建号：否则管理员可以往别的租户塞人
    if req.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=403, detail="CROSS_TENANT_FORBIDDEN")
    if users.get_by_email(db, req.email) is not None:
        raise HTTPException(status_code=409, detail="EMAIL_ALREADY_EXISTS")

    problem = users.validate_password(req.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    users.ensure_tenant(db, req.tenant_id, req.tenant_id)
    user = users.create_user(
        db,
        email=req.email,
        password=req.password,
        tenant_id=req.tenant_id,
        roles=req.roles,
        on_behalf_of=req.on_behalf_of,
    )
    return _user_item(user)


@router.post("/users/{user_id}/roles", response_model=AdminUserItem)
def set_user_roles(
    user_id: str,
    req: SetRolesRequest,
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> AdminUserItem:
    user = _load_tenant_user(db, user_id, principal)
    users.set_roles(db, user, req.roles)
    # 角色变了就下线该用户的刷新令牌；已签发的访问令牌最长 15 分钟后失效
    session_service.revoke_all_for_user(db, user.id)
    return _user_item(user)


@router.post("/users/{user_id}/status", response_model=AdminUserItem)
def set_user_status(
    user_id: str,
    req: SetStatusRequest,
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> AdminUserItem:
    if req.status not in {"active", "disabled"}:
        raise HTTPException(status_code=400, detail="INVALID_STATUS")

    user = _load_tenant_user(db, user_id, principal)
    if user.id == principal.user_id:
        raise HTTPException(status_code=400, detail="CANNOT_MODIFY_SELF")

    users.set_status(db, user, req.status)
    if req.status == "disabled":
        session_service.revoke_all_for_user(db, user.id)
    return _user_item(user)


@router.post("/users/{user_id}/scope", response_model=AdminUserItem)
def set_user_scope(
    user_id: str,
    req: SetScopeRequest,
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> AdminUserItem:
    """绑定该账号代理的客户（代理授权的最小实现）。

    真正的“按会话申领客户 + ACL 校验”还没做，见 docs/implementation-status.md。
    """
    user = _load_tenant_user(db, user_id, principal)
    users.set_scope(db, user, req.on_behalf_of)
    # 客户范围变了，旧令牌必须作废
    session_service.revoke_all_for_user(db, user.id)
    return _user_item(user)


@router.post("/users/{user_id}/adopt", response_model=AdminUserItem)
def adopt_user(
    user_id: str,
    req: AdoptUserRequest,
    principal: Principal = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> AdminUserItem:
    """把自注册账号纳入本租户（自助注册 → 被邀请加入）。

    只允许针对公共租户里的账号操作，否则就是跨租户提权。
    """
    target = users.get_by_id(db, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    if target.tenant_id != settings.default_signup_tenant:
        raise HTTPException(status_code=403, detail="ADOPT_ONLY_PUBLIC_TENANT")
    if (target.status or "").lower() != "active":
        raise HTTPException(status_code=400, detail="USER_NOT_ACTIVE")

    users.adopt_into_tenant(
        db,
        target,
        tenant_id=principal.tenant_id,
        roles=req.roles,
        on_behalf_of=req.on_behalf_of,
    )
    session_service.revoke_all_for_user(db, target.id)
    return _user_item(target)


@router.post("/dev-token", response_model=TokenResponse)
def dev_token(req: DevTokenRequest) -> TokenResponse:
    """本机调试用的身份后门：默认关闭，且只在 dev 环境可用。"""
    if settings.app_env != "dev" or not settings.allow_dev_token:
        raise HTTPException(status_code=403, detail="DEV_TOKEN_DISABLED")

    access_token, claims = issue_access_token(
        user_id=req.user_id,
        tenant_id=req.tenant_id,
        roles=req.roles,
        agent_id=req.agent_id or req.user_id,
        on_behalf_of=req.on_behalf_of,
        ttl_seconds=req.ttl_seconds,
    )
    principal = Principal(
        user_id=req.user_id,
        tenant_id=req.tenant_id,
        roles=tuple(req.roles),
        agent_id=req.agent_id or req.user_id,
        on_behalf_of=req.on_behalf_of,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token="",
        expires_in=claims["exp"] - claims["iat"],
        principal=_principal_payload(principal),
    )
