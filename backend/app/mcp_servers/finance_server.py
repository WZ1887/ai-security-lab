"""财务 MCP Server。

提供 transfer_funds 工具。
高风险，需人工审批。
"""

from app.mcp_servers.base import BaseMCPServer, ToolSpec


_TRANSFERS: list[dict] = []


def _transfer_funds(args: dict) -> dict:
    to = str(args.get("to", "")).strip()
    amount = float(args.get("amount", 0))

    if not to:
        return {"error": "invalid_account"}
    if amount <= 0:
        return {"error": "invalid_amount", "amount": amount}

    record = {"to": to, "amount": amount, "status": "ok"}
    _TRANSFERS.append(record)
    return record


def _transfer_count() -> int:
    return len(_TRANSFERS)


class FinanceServer(BaseMCPServer):
    server_id = "finance-server"
    fingerprint = "sha256:finance-server-v1"

    def _register(self) -> None:
        self.add_tool(
            ToolSpec(
                name="transfer_funds",
                description="Transfer funds between accounts",
                input_schema={"to": "str", "amount": "float"},
                capability="write:funds",
                output_labels=["FINANCIAL"],
                risk_level="high",
                handler=_transfer_funds,
            )
        )