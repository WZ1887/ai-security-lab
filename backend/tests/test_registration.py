"""自注册 + 管理员用户/角色管理。

关键断言：自注册只能拿到最低权限（customer），特权角色必须由管理员授予。

注：TestClient 的请求跑在独立线程里，测试引擎偶尔会在 GC 时打印一条 SQLite
跨线程告警——不影响断言结果，属于测试台自身的现象。
"""

import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import NullPool

from app.mcp_guard.registry.sync import sync_from_servers
from app.main import app
from app.models import approval, audit_event, policy_rule, tool_registry, user  # noqa: F401
from app.models.base import Base
from app.models.db import get_db
from app.security import ratelimit, users


def _client() -> TestClient:
    db_path = Path(tempfile.mkdtemp(prefix="mcpguard_reg_")) / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    db = SessionLocal()
    sync_from_servers(db)
    users.seed_demo_users(db)
    db.close()

    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    ratelimit.reset_for_test()
    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = _get_db
    return TestClient(app)


def _register(client, email="newbie@example.com", password="Passw0rd!"):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def _login(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


# ---------- 自注册 ----------

def test_register_verify_then_login_with_zero_privileges():
    client = _client()

    reg = _register(client)
    assert reg.status_code == 202
    token = reg.json()["verification_token"]
    assert token

    # 未验证不能登录
    pending = _login(client, "newbie@example.com", "Passw0rd!")
    assert pending.status_code == 401
    assert pending.json()["detail"] == "EMAIL_NOT_VERIFIED"

    verified = client.post("/api/auth/verify-email", json={"token": token})
    assert verified.status_code == 200
    principal = verified.json()["principal"]
    assert principal["roles"] == ["customer"]
    assert principal["tenant_id"] == "tenant_public"
    assert principal["on_behalf_of"] == ""

    # 自注册账号没有任何工具权限：G3 过了，G4 的 RBAC 拦下
    import app.api.chat as chat_api
    from app.agent.planner import PlanResult

    original = chat_api.plan
    try:
        chat_api.plan = lambda text, tools, **kw: PlanResult(
            tool_name="get_order", arguments={"order_id": "10023"}, reason="OK"
        )
        blocked = client.post(
            "/api/chat",
            headers={"Authorization": "Bearer " + verified.json()["access_token"]},
            json={"session_id": "s1", "user_input": "查订单 #10023"},
        ).json()
        assert blocked["blocked"]
        assert blocked["blocked_reason"] == "G4_TOOL_NOT_IN_ROLE"
    finally:
        chat_api.plan = original


def test_register_does_not_reveal_existing_email():
    client = _client()
    first = _register(client, email="dup@example.com")
    second = _register(client, email="dup@example.com")

    assert first.status_code == second.status_code == 202
    assert first.json()["status"] == second.json()["status"]
    # 已存在的邮箱不再签发新令牌
    assert first.json()["verification_token"]
    assert second.json()["verification_token"] is None


def test_register_input_validation():
    client = _client()
    assert _register(client, password="short").json()["detail"] == "PASSWORD_TOO_SHORT"
    assert _register(client, password="onlyletters").json()["detail"] == "PASSWORD_NEEDS_DIGIT"
    assert _register(client, password="12345678").json()["detail"] == "PASSWORD_NEEDS_LETTER"
    assert _register(client, email="not-an-email").json()["detail"] == "INVALID_EMAIL"


def test_register_is_rate_limited_per_ip():
    client = _client()
    codes = [
        _register(client, email=f"bulk{i}@example.com").status_code
        for i in range(6)
    ]
    assert codes[:5] == [202] * 5
    assert codes[5] == 429


def test_resend_verification():
    client = _client()
    first = _register(client, email="resend@example.com").json()["verification_token"]

    resent = client.post(
        "/api/auth/resend-verification", json={"email": "resend@example.com"}
    ).json()
    assert resent["verification_token"] and resent["verification_token"] != first

    # 不存在的邮箱返回同样的结构，不泄露账号是否存在
    ghost = client.post(
        "/api/auth/resend-verification", json={"email": "ghost@example.com"}
    ).json()
    assert ghost["status"] == resent["status"]
    assert ghost["verification_token"] is None


# ---------- 管理员管理 ----------

def test_admin_creates_user_grants_roles_and_disables():
    client = _client()
    manager = _login(client, "manager01@example.com", "Demo1234!").json()
    MH = {"Authorization": "Bearer " + manager["access_token"]}
    cs = _login(client, "cs01@example.com", "Demo1234!").json()
    CH = {"Authorization": "Bearer " + cs["access_token"]}

    # 非管理员不能管理用户
    assert client.get("/api/auth/users", headers=CH).status_code == 403

    created = client.post(
        "/api/auth/users",
        headers=MH,
        json={
            "email": "agent02@example.com",
            "password": "Passw0rd!",
            "tenant_id": "tenant_001",
            "roles": ["cs_agent"],
            "on_behalf_of": "user_001",
        },
    )
    assert created.status_code == 201
    body = created.json()
    user_id = body["user_id"]
    assert body["roles"] == ["cs_agent"]
    assert body["on_behalf_of"] == "user_001"
    assert body["email_verified"] is True      # 管理员建号视为已验证
    assert body["status"] == "active"

    # 管理员建号后该账号能直接登录
    assert _login(client, "agent02@example.com", "Passw0rd!").status_code == 200

    # 跨租户建号被拒
    cross = client.post(
        "/api/auth/users",
        headers=MH,
        json={
            "email": "spy@example.com",
            "password": "Passw0rd!",
            "tenant_id": "tenant_002",
            "roles": ["cs_agent"],
        },
    )
    assert cross.status_code == 403
    assert cross.json()["detail"] == "CROSS_TENANT_FORBIDDEN"

    # 改角色 → 该用户刷新令牌作废
    tokens = _login(client, "agent02@example.com", "Passw0rd!").json()
    downgraded = client.post(
        f"/api/auth/users/{user_id}/roles", headers=MH, json={"roles": []}
    )
    assert downgraded.json()["roles"] == []
    assert client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401

    # 停用后不能登录
    disabled = client.post(
        f"/api/auth/users/{user_id}/status", headers=MH, json={"status": "disabled"}
    )
    assert disabled.json()["status"] == "disabled"
    blocked = _login(client, "agent02@example.com", "Passw0rd!")
    assert blocked.status_code == 401
    assert blocked.json()["detail"] == "ACCOUNT_DISABLED"

    # 管理员不能停用自己
    me = client.get("/api/auth/me", headers=MH).json()
    assert client.post(
        f"/api/auth/users/{me['user_id']}/status", headers=MH, json={"status": "disabled"}
    ).status_code == 400


def test_admin_binds_agent_scope_and_list_is_tenant_scoped():
    client = _client()
    manager = _login(client, "manager01@example.com", "Demo1234!").json()
    MH = {"Authorization": "Bearer " + manager["access_token"]}

    listed = client.get("/api/auth/users", headers=MH).json()
    emails = {u["email"] for u in listed}
    assert "cs01@example.com" in emails
    assert "cs02@example.com" not in emails      # tenant_002 的账号不可见

    cs_user = next(u for u in listed if u["email"] == "cs01@example.com")
    rebound = client.post(
        f"/api/auth/users/{cs_user['user_id']}/scope", headers=MH, json={"on_behalf_of": ""}
    )
    assert rebound.json()["on_behalf_of"] == ""


def test_admin_adopts_self_registered_user_into_tenant():
    """自注册账号落在公共租户、零权限；管理员可把它纳入本租户并授权。"""
    import app.api.chat as chat_api
    from app.agent.planner import PlanResult

    client = _client()
    reg = _register(client, email="adoptee@example.com").json()
    verified = client.post(
        "/api/auth/verify-email", json={"token": reg["verification_token"]}
    ).json()
    user_id = verified["principal"]["user_id"]
    assert verified["principal"]["tenant_id"] == "tenant_public"

    manager = _login(client, "manager01@example.com", "Demo1234!").json()
    MH = {"Authorization": "Bearer " + manager["access_token"]}

    # 管理员看不到别的租户的账号（租户隔离）
    listed = client.get("/api/auth/users", headers=MH).json()
    assert "adoptee@example.com" not in {u["email"] for u in listed}

    adopted = client.post(
        f"/api/auth/users/{user_id}/adopt",
        headers=MH,
        json={"roles": ["cs_agent"], "on_behalf_of": "user_001"},
    )
    assert adopted.status_code == 200
    body = adopted.json()
    assert body["tenant_id"] == "tenant_001"
    assert body["roles"] == ["cs_agent"]
    assert body["on_behalf_of"] == "user_001"

    # 重新登录后按代理范围可以读客户的订单
    tokens = _login(client, "adoptee@example.com", "Passw0rd!").json()
    assert tokens["principal"]["tenant_id"] == "tenant_001"
    assert tokens["principal"]["resource_user_id"] == "user_001"

    original_plan = chat_api.plan
    try:
        chat_api.plan = lambda text, tools, **kw: PlanResult(
            tool_name="get_order", arguments={"order_id": "10023"}, reason="OK"
        )
        resp = client.post(
            "/api/chat",
            headers={"Authorization": "Bearer " + tokens["access_token"]},
            json={"session_id": "s9", "user_input": "查订单 #10023"},
        ).json()
        assert not resp["blocked"], resp
        assert "10023" in resp["reply"]
    finally:
        chat_api.plan = original_plan

    # 已在真实租户里的账号不能再被“纳入”一次（否则就是跨租户提权）
    again = client.post(
        f"/api/auth/users/{user_id}/adopt", headers=MH, json={"roles": ["admin"]}
    )
    assert again.status_code == 403
    assert again.json()["detail"] == "ADOPT_ONLY_PUBLIC_TENANT"


# ---------- 改密 ----------

def test_change_password_requires_current_and_revokes_sessions():
    client = _client()
    tokens = _login(client, "cs01@example.com", "Demo1234!").json()
    H = {"Authorization": "Bearer " + tokens["access_token"]}

    wrong = client.post(
        "/api/auth/password",
        headers=H,
        json={"current_password": "wrong", "new_password": "Passw0rd!"},
    )
    assert wrong.status_code == 400
    assert wrong.json()["detail"] == "INVALID_CREDENTIALS"

    same = client.post(
        "/api/auth/password",
        headers=H,
        json={"current_password": "Demo1234!", "new_password": "Demo1234!"},
    )
    assert same.json()["detail"] == "PASSWORD_UNCHANGED"

    changed = client.post(
        "/api/auth/password",
        headers=H,
        json={"current_password": "Demo1234!", "new_password": "Passw0rd!"},
    )
    assert changed.status_code == 200

    # 旧刷新令牌被撤销
    assert client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401
    # 新口令可登录，旧口令不可
    assert _login(client, "cs01@example.com", "Passw0rd!").status_code == 200
    assert _login(client, "cs01@example.com", "Demo1234!").status_code == 401
