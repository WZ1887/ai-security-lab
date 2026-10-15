import asyncio
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.approvals import router as approvals_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.chat import router as chat_router
from app.api.memory import router as memory_router
from app.config import REPO_ROOT as _REPO_ROOT
from app.config import Settings, settings  # noqa: F401  (Settings 保留给外部引用)


def _check_security_config() -> None:
    """弱配置检查：dev 只告警，其他环境直接拒绝启动。

    PyJWT 对 < 32 字节的 HMAC 密钥会告警（RFC 7518 §3.2），
    而 .env.example 里的占位符往往会被原样带到生产。
    """
    problems = []
    if len(settings.jwt_secret.encode("utf-8")) < 32:
        problems.append("JWT_SECRET 少于 32 字节")
    if len(settings.approval_token_secret.encode("utf-8")) < 32:
        problems.append("APPROVAL_TOKEN_SECRET 少于 32 字节")
    if not problems:
        return

    message = "；".join(problems)
    if settings.app_env == "dev":
        print(f"[security] 弱配置（dev 环境仅告警）：{message}")
    else:
        raise RuntimeError(f"安全配置不合法，拒绝启动：{message}")


def _init_startup_data() -> None:
    """启动初始化：同步工具注册表（dev 环境再补齐演示账号）。

    fail-soft：数据库不可用时只打日志，不影响进程启动。
    注册表为空时 G3 会拒绝所有工具调用，属于 fail-closed，不会误放行。
    """
    _check_security_config()
    try:
        from app.mcp_guard.registry.sync import sync_from_servers
        from app.models.db import SessionLocal

        db = SessionLocal()
        try:
            count = sync_from_servers(db)
            seeded = 0
            if settings.app_env == "dev":
                from app.security.users import seed_demo_users

                seeded = seed_demo_users(db)
        finally:
            db.close()
        print(f"[registry] 已同步 {count} 个工具")
        if seeded:
            print(f"[auth] 新增 {seeded} 个演示账号（仅 dev 环境）")
    except Exception as e:
        print(f"[startup] 初始化跳过：{type(e).__name__}: {e}")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _init_startup_data()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "env": settings.app_env,
        "version": settings.app_version,
        "model": settings.ollama_model,
    }


def _probe_db() -> str:
    try:
        from sqlalchemy import text

        from app.models.db import engine

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as e:
        return f"unavailable:{type(e).__name__}"


async def _probe_ollama() -> str:
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=1.5) as client:
            r = await client.get(f"{settings.ollama_host}/api/tags")
        return "ok" if r.status_code < 400 else f"http_{r.status_code}"
    except Exception as e:
        return f"unavailable:{type(e).__name__}"


@app.get("/health/deps")
async def health_deps():
    """依赖探活：数据库不可用 → 工具注册表为空 → G3 会拒绝所有调用（fail-closed）。"""
    database = await asyncio.to_thread(_probe_db)
    ollama = await _probe_ollama()
    return {
        "status": "ok" if database == "ok" else "degraded",
        "database": database,
        "ollama": ollama,
        "tools_blocked_when_db_down": database != "ok",
        "semantic_degraded_when_ollama_down": ollama != "ok",
    }


# ---------- API 路由 ----------
app.include_router(chat_router)
app.include_router(audit_router)
app.include_router(approvals_router)
app.include_router(auth_router)
app.include_router(memory_router)


# ---------- 前端静态文件 ----------
_FRONTEND_DIR = _REPO_ROOT / "frontend"

if _FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
