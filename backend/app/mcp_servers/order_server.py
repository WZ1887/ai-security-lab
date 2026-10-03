"""订单 MCP Server。

提供 get_order 工具。
数据是内存假数据，用于靶场演示。
"""

from app.mcp_servers.base import BaseMCPServer, ToolSpec


_ORDERS: dict[str, dict] = {
    "10023": {
        "order_id": "10023",
        "user_id": "user_001",
        "status": "shipped",
        "amount": 199.0,
        "phone": "13812345678",
        "address": "北京市朝阳区XX路1号",
    },
    "10024": {
        "order_id": "10024",
        "user_id": "user_002",
        "status": "pending",
        "amount": 88.0,
        "phone": "13987654321",
        "address": "上海市浦东新区YY路2号",
    },
}


def _get_order(args: dict) -> dict:
    oid = str(args.get("order_id", ""))
    order = _ORDERS.get(oid)
    if order is None:
        return {"error": "order_not_found", "order_id": oid}
    return order


class OrderServer(BaseMCPServer):
    server_id = "order-server"
    fingerprint = "sha256:order-server-v1"

    def _register(self) -> None:
        self.add_tool(
            ToolSpec(
                name="get_order",
                description="Get order details by order id",
                input_schema={"order_id": "str"},
                capability="read:order",
                output_labels=["PII", "ORDER_DATA"],
                risk_level="low",
                handler=_get_order,
            )
        )