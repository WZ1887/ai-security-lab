"""应用配置（叶子模块）。

放在这里而不是 app/main.py 的原因：embedder / planner / db / security 等模块都要读配置，
如果它们 `from app.main import settings`，就会把 app.main（及其 API 路由）拖进导入链，
任何“先 import 某个 guard 模块”的用法都会触发循环导入。
app.config 只依赖 pydantic-settings，谁都可以安全地导入它。
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# 仓库根目录：配置与静态资源都锚定在这里，不再依赖进程 CWD
REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=REPO_ROOT / ".env", extra="ignore")

    app_env: str = "dev"
    app_name: str = "MCP-Guard"
    app_version: str = "0.1.0"

    database_url: str = "postgresql+psycopg2://mcp:mcp_dev_password@localhost:5432/mcp_guard"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    ollama_embed: str = "nomic-embed-text"

    jwt_secret: str = "change_me"
    jwt_alg: str = "HS256"
    access_token_ttl: int = 900
    refresh_token_ttl: int = 604800

    # G5 审批令牌
    approval_token_secret: str = "mcp-guard-approval-secret-change-in-prod"
    approval_token_ttl_seconds: int = 300

    # G5 沙箱
    sandbox_root: str = ""            # 留空 = 仓库根下的 sandbox_root
    sandbox_max_arg_chars: int = 8192

    # 认证
    allow_dev_token: bool = False     # 仅本地演示需要时打开
    login_max_failed_attempts: int = 5
    login_lockout_seconds: int = 900
    mfa_issuer: str = "MCP-Guard"

    # 自注册（只能拿到最低权限；特权角色必须由管理员授予）
    allow_self_registration: bool = True
    default_signup_tenant: str = "tenant_public"
    verification_token_ttl_seconds: int = 86400
    register_rate_limit_max: int = 5
    register_rate_limit_window_seconds: int = 900
    password_min_length: int = 8

    # 记忆（只存事实）
    memory_recall_limit: int = 20


settings = Settings()
