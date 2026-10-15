"""兼容层：真正的注册表同步已移到 registry/sync.py。

保留 seed_all 这个名字，避免外部脚本 import 时炸掉。
"""

from sqlalchemy.orm import Session

from app.mcp_guard.registry.sync import sync_from_servers


def seed_all(db: Session) -> None:
    """幂等写入 tool_registry（等价于 sync_from_servers）。"""
    sync_from_servers(db)
