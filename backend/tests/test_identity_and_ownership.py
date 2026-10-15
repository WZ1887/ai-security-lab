"""身份与资源归属：令牌解析 + 工具级越权拦截。

不需要数据库，也不需要 Ollama。
"""

from app.mcp_servers.context import CallContext
from app.mcp_servers.order_server import OrderServer
from app.security.principal import (
    TokenError,
    decode_access_token,
    issue_access_token,
    principal_from_claims,
)


def _ctx(user_id: str, tenant_id: str) -> CallContext:
    return CallContext(
        user_id=user_id,
        tenant_id=tenant_id,
        agent_id="agent",
        session_id="sess",
    )


def _expect_token_error(token: str, expected_reason: str) -> None:
    try:
        decode_access_token(token)
    except TokenError as e:
        assert e.reason == expected_reason, e.reason
        return
    raise AssertionError(f"expected TokenError({expected_reason})")


def test_token_roundtrip_builds_principal():
    token, _ = issue_access_token(
        user_id="user_001",
        tenant_id="tenant_001",
        roles=["cs_agent"],
        agent_id="cs_agent_01",
    )
    principal = principal_from_claims(decode_access_token(token))
    assert principal.user_id == "user_001"
    assert principal.tenant_id == "tenant_001"
    assert principal.roles == ("cs_agent",)
    assert principal.agent_id == "cs_agent_01"
    assert principal.to_call_context("sess_1").tenant_id == "tenant_001"


def test_tampered_token_rejected():
    token, _ = issue_access_token(user_id="user_001", tenant_id="tenant_001")
    _expect_token_error(token[:-3] + "aaa", "INVALID_TOKEN")


def test_expired_token_rejected():
    token, _ = issue_access_token(user_id="user_001", tenant_id="tenant_001", ttl_seconds=-1)
    _expect_token_error(token, "TOKEN_EXPIRED")


def test_order_is_owner_and_tenant_scoped():
    order = OrderServer()

    own = order.call_tool("get_order", {"order_id": "10023"}, _ctx("user_001", "tenant_001"))
    assert own["order_id"] == "10023"

    # 别人的订单、跨租户、无身份：都拿不到数据，且与“订单不存在”不可区分
    for ctx in (
        _ctx("user_002", "tenant_002"),
        _ctx("user_002", "tenant_001"),
        _ctx("user_001", "tenant_999"),
        CallContext(),
    ):
        res = order.call_tool("get_order", {"order_id": "10023"}, ctx)
        assert res.get("error") == "order_not_found", (ctx, res)
        assert "phone" not in res
