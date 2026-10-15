"""工具注册表同步。

单一事实来源：工具的 description / input_schema / output_schema / capability /
version / risk_level / output_labels 只写在 MCP Server 的 ToolSpec 里，
tool_registry 表由 Server 派生。

背景：这些元数据曾经在 seed.py、api/chat.py、mcp_servers 里各存一份副本，
改一处忘一处就会让 G3 的哈希校验全线失败（表现为所有工具调用被拒）。

用法：
    from app.mcp_guard.registry.sync import sync_from_servers
    sync_from_servers(db)          # 幂等

    # 或手动执行（需要可用的 DATABASE_URL）
    python -m app.mcp_guard.registry.sync
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.mcp_guard.registry.g3 import compute_hash
from app.mcp_servers.base import BaseMCPServer
from app.mcp_servers.email_server import EmailServer
from app.mcp_servers.finance_server import FinanceServer
from app.mcp_servers.kb_server import KnowledgeServer
from app.mcp_servers.memory_server import MemoryServer
from app.mcp_servers.order_server import OrderServer
from app.models.tool_registry import ToolRegistry


def default_servers() -> list[BaseMCPServer]:
    """靶场内置的 MCP Server 集合。"""
    return [
        OrderServer(),
        KnowledgeServer(),
        EmailServer(),
        FinanceServer(),
        MemoryServer(),
    ]


def build_registry_rows(servers: list[BaseMCPServer] | None = None) -> list[dict]:
    """把 Server 的 ToolSpec 拍平成 tool_registry 行（纯函数，不碰数据库）。"""
    servers = default_servers() if servers is None else servers
    approved_at = datetime.utcnow()
    rows: list[dict] = []
    for server in servers:
        for spec in server.list_tools():
            rows.append(
                {
                    "server_id": server.server_id,
                    "server_fingerprint": server.fingerprint,
                    "tool_name": spec.name,
                    "tool_version": spec.version,
                    "description_hash": compute_hash(spec.description),
                    "input_schema_hash": compute_hash(spec.input_schema),
                    "output_schema_hash": compute_hash(spec.output_schema or {}),
                    "capability_hash": compute_hash(spec.capability),
                    "risk_level": spec.risk_level,
                    "output_labels": ",".join(spec.output_labels),
                    "approved": True,
                    "approved_by": "system:registry-sync",
                    "approved_at": approved_at,
                }
            )
    return rows


def build_tool_index(servers: list[BaseMCPServer] | None = None) -> dict[str, dict]:
    """tool_name -> 调用侧需要的元数据（含执行器）。

    调用侧（api/chat.py）用它拿哈希和 executor，避免再写一份副本。
    这里算出的哈希代表“Server 当前声明的元数据”，
    G3 会拿它和注册表里的值比对，两边不一致即在 G3 拦截。
    """
    servers = default_servers() if servers is None else servers
    index: dict[str, dict] = {}
    for server in servers:
        for spec in server.list_tools():
            index[spec.name] = {
                "server_id": server.server_id,
                "server_fingerprint": server.fingerprint,
                "tool_version": spec.version,
                "description": spec.description,
                "input_schema": spec.input_schema,
                "output_schema": spec.output_schema,
                "description_hash": compute_hash(spec.description),
                "input_schema_hash": compute_hash(spec.input_schema),
                "output_schema_hash": compute_hash(spec.output_schema or {}),
                "capability_hash": compute_hash(spec.capability),
                "risk_level": spec.risk_level,
                "output_labels": list(spec.output_labels),
                "executor": server.call_tool,
            }
    return index


def sync_from_servers(
    db: Session,
    servers: list[BaseMCPServer] | None = None,
) -> int:
    """把 tool_registry 更新到与 Server 定义一致，返回处理的工具数。"""
    rows = build_registry_rows(servers)
    for row in rows:
        existing = (
            db.query(ToolRegistry)
            .filter(ToolRegistry.server_id == row["server_id"])
            .filter(ToolRegistry.tool_name == row["tool_name"])
            .first()
        )
        if existing is None:
            db.add(ToolRegistry(**row))
            continue
        for key, value in row.items():
            setattr(existing, key, value)
    db.commit()
    return len(rows)


def main() -> None:
    """手动同步入口：python -m app.mcp_guard.registry.sync"""
    from app.models.db import SessionLocal

    db = SessionLocal()
    try:
        count = sync_from_servers(db)
    finally:
        db.close()
    print(f"tool_registry 已同步：{count} 个工具")


if __name__ == "__main__":
    main()
