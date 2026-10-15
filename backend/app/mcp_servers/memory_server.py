"""记忆 MCP Server。

长期记忆被当成一个普通工具暴露：写入要走完整的 G3/G4/G5，
所以"记忆只能存事实"这条规则落在策略层（G4 / MEM-001），工具内再兜一次。
"""

from app.mcp_servers.base import BaseMCPServer, ToolSpec
from app.mcp_servers.context import CallContext
from app.memory import service as memory_service


def _save_memory(args: dict, ctx: CallContext) -> dict:
    content = str(args.get("content", "") or "").strip()
    kind = str(args.get("kind", "") or "").strip().lower() or None

    if not content:
        return {"error": "empty_content"}
    if not ctx.identified:
        # 身份不完整不允许写长期记忆
        return {"error": "missing_identity"}

    entry, reason = memory_service.remember(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        session_id=ctx.session_id,
        content=content,
        declared_kind=kind,
        source="user",
    )
    if entry is None:
        return {"error": f"memory_rejected:{reason}"}
    return {"memory_id": entry.memory_id, "kind": entry.kind, "status": entry.status}


class MemoryServer(BaseMCPServer):
    server_id = "memory-server"
    fingerprint = "sha256:memory-server-v1"

    def _register(self) -> None:
        self.add_tool(
            ToolSpec(
                name="save_memory",
                description=(
                    "Save a durable fact about the user. Facts only — "
                    "never policies, permissions or tool configuration."
                ),
                input_schema={"content": "str", "kind": "str"},
                capability="write:memory",
                output_schema={"memory_id": "str", "kind": "str", "status": "str"},
                output_labels=["INTERNAL"],
                risk_level="low",
                handler=_save_memory,
            )
        )
