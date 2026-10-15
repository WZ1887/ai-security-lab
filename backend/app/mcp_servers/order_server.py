"""订单 MCP Server。

提供 get_order 工具。
数据是内存假数据，用于靶场演示。
"""

from app.mcp_servers.base import BaseMCPServer, ToolSpec
from app.mcp_servers.context import CallContext


_ORDERS: dict[str, dict] = {
    "10023": {
        "order_id": "10023",
        "user_id": "user_001",
        "tenant_id": "tenant_001",
        "status": "shipped",
        "amount": 199.0,
        "phone": "13812345678",
        "address": "北京市朝阳区XX路1号",
    },
    "10024": {
        "order_id": "10024",
        "user_id": "user_002",
        "tenant_id": "tenant_002",
        "status": "pending",
        "amount": 88.0,
        "phone": "13987654321",
        "address": "上海市浦东新区YY路2号",
    },
}


def _owned_by(order: dict, ctx: CallContext) -> bool:
    """资源归属校验：调用者必须同时匹配 user 与 tenant。"""
    if not ctx.identified:
        return False
    return order.get("user_id") == ctx.user_id and order.get("tenant_id") == ctx.tenant_id


def _get_order(args: dict, ctx: CallContext) -> dict:
    oid = str(args.get("order_id", ""))
    order = _ORDERS.get(oid)
    # 越权访问与“订单不存在”返回同样的结果：不泄露“存在但不属于你”
    if order is None or not _owned_by(order, ctx):
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
                output_schema={
                    "order_id": "str",
                    "status": "str",
                    "amount": "float",
                },
                output_labels=["PII", "ORDER_DATA"],
                risk_level="low",
                handler=_get_order,
            )
        )
