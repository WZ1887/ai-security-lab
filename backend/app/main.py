from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"
    app_name: str = "MCP-Guard"
    app_version: str = "0.1.0"

    database_url: str = "postgresql+psycopg2://mcp:mcp_dev_password@localhost:5432/mcp_guard"
    redis_url: str = "redis://localhost:6379/0"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    ollama_embed: str = "nomic-embed-text"

    jwt_secret: str = "change_me"
    jwt_alg: str = "HS256"
    access_token_ttl: int = 900
    refresh_token_ttl: int = 604800


settings = Settings()

app = FastAPI(title=settings.app_name, version=settings.app_version)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "env": settings.app_env,
        "version": settings.app_version,
        "model": settings.ollama_model,
    }


# ---------- API 路由 ----------
from app.api.chat import router as chat_router
from app.api.audit import router as audit_router

app.include_router(chat_router)
app.include_router(audit_router)


# ---------- 前端静态文件 ----------
_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

if _FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")