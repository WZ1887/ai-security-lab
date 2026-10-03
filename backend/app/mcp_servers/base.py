"""MCP Server 简化基类（MVP）。

不直接实现完整 MCP 协议，用 Python 类模拟。
每个 Server：
  - 声明 tools 列表（含 name / description / input_schema）
  - 提供 call_tool(name, arguments) -> dict
后续可替换为真正的 MCP Python SDK。
"""

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    capability: str
    output_labels: list[str] = field(default_factory=list)
    risk_level: str = "low"
    handler: Callable[[dict], dict] | None = None


class BaseMCPServer:
    server_id: str = "base-server"
    fingerprint: str = "sha256:base-v1"

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._register()

    def _register(self) -> None:
        raise NotImplementedError

    def add_tool(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def list_tools(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def get_tool(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def call_tool(self, name: str, arguments: dict) -> dict:
        spec = self._tools.get(name)
        if spec is None:
            return {"error": f"tool_not_found:{name}"}
        if spec.handler is None:
            return {"error": f"tool_has_no_handler:{name}"}
        try:
            return spec.handler(arguments)
        except Exception as e:
            return {"error": f"{type(e).__name__}:{e}"}