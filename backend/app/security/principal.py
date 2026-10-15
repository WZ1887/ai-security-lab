"""访问令牌与身份主体（Principal）。

身份的唯一来源是签名令牌。请求体里的 user_id / roles / tenant_id 一律不采信，
否则 RBAC、委派范围、资源归属校验都可以被客户端伪造。

令牌格式：标准 JWT（HS256），用 PyJWT 签发与校验。
运维脚本 / 回归测试可以直接用 issue_access_token 造令牌；
浏览器端走 dev 环境专用的 /api/auth/dev-token（见 app/api/auth.py）。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

import jwt
from fastapi import Header, HTTPException

from app.config import settings
from app.mcp_servers.context import CallContext


ISSUER = "mcp-guard"


class TokenError(Exception):
    """令牌校验失败，reason 是稳定的错误码（可直接进审计）。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    agent_id: str = ""
    # 代理调用：被代理的客户 id（客服代客操作时为客户的 user_id）
    on_behalf_of: str = ""

    def has_any_role(self, allowed: set[str]) -> bool:
        return bool(allowed.intersection(self.roles))

    @property
    def resource_user_id(self) -> str:
        """资源归属判定用的用户：代理场景下是被代理的客户，否则是本人。

        只影响“以谁的身份访问数据”，不影响“谁在操作”（后者是 user_id/agent_id，
        会写进审计）。
        """
        return self.on_behalf_of or self.user_id

    def to_call_context(self, session_id: str) -> CallContext:
        return CallContext(
            user_id=self.resource_user_id,
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            session_id=session_id,
            roles=tuple(self.roles),
        )


def issue_access_token(
    *,
    user_id: str,
    tenant_id: str,
    roles: list[str] | None = None,
    agent_id: str = "",
    on_behalf_of: str = "",
    ttl_seconds: int | None = None,
) -> tuple[str, dict]:
    """签发访问令牌，返回 (token, claims)。"""
    now = int(time.time())
    ttl = ttl_seconds or settings.access_token_ttl
    claims = {
        "iss": ISSUER,
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": [str(r) for r in (roles or [])],
        "agent_id": agent_id or user_id,
        "on_behalf_of": on_behalf_of or "",
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_alg)
    return token, claims


def decode_access_token(token: str) -> dict:
    """校验签名 / 过期 / issuer，返回 claims。"""
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_alg],
            issuer=ISSUER,
            options={"require": ["exp", "sub", "tenant_id"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenError("TOKEN_EXPIRED") from e
    except jwt.InvalidTokenError as e:
        raise TokenError("INVALID_TOKEN") from e


def principal_from_claims(claims: dict) -> Principal:
    roles = claims.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]
    return Principal(
        user_id=str(claims.get("sub") or ""),
        tenant_id=str(claims.get("tenant_id") or ""),
        roles=tuple(str(r) for r in roles),
        agent_id=str(claims.get("agent_id") or ""),
        on_behalf_of=str(claims.get("on_behalf_of") or ""),
    )


def get_principal(authorization: str | None = Header(default=None)) -> Principal:
    """FastAPI 依赖：从 `Authorization: Bearer <jwt>` 解析身份。"""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="MISSING_BEARER_TOKEN",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = decode_access_token(token)
    except TokenError as e:
        raise HTTPException(
            status_code=401,
            detail=e.reason,
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    principal = principal_from_claims(claims)
    if not principal.user_id or not principal.tenant_id:
        raise HTTPException(status_code=401, detail="INCOMPLETE_IDENTITY")
    return principal
