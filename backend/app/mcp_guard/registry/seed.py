"""向 tool_registry 插入测试工具。幂等：已存在则更新。"""

from sqlalchemy.orm import Session

from app.models.tool_registry import ToolRegistry
from app.mcp_guard.registry.g3 import compute_hash


def _upsert(db: Session, data: dict) -> None:
    existing = (
        db.query(ToolRegistry)
        .filter(ToolRegistry.server_id == data["server_id"])
        .filter(ToolRegistry.tool_name == data["tool_name"])
        .first()
    )
    if existing is None:
        db.add(ToolRegistry(**data))
    else:
        for k, v in data.items():
            setattr(existing, k, v)
    db.commit()


def seed_all(db: Session) -> None:
    tools = [
        {
            "server_id": "order-server",
            "server_fingerprint": "sha256:order-server-v1",
            "tool_name": "get_order",
            "tool_version": "1.0.0",
            "description_hash": compute_hash("Get order details by order id"),
            "input_schema_hash": compute_hash({"order_id": "str"}),
            "output_schema_hash": compute_hash({"order_id": "str", "status": "str", "amount": "float"}),
            "capability_hash": compute_hash("read:order"),
            "risk_level": "low",
            "output_labels": "PII,ORDER_DATA",
            "approved": True,
            "approved_by": "admin",
        },
        {
            "server_id": "kb-server",
            "server_fingerprint": "sha256:kb-server-v1",
            "tool_name": "search_knowledge",
            "tool_version": "1.0.0",
            "description_hash": compute_hash("Search knowledge base"),
            "input_schema_hash": compute_hash({"query": "str"}),
            "output_schema_hash": compute_hash({"results": "list"}),
            "capability_hash": compute_hash("read:kb"),
            "risk_level": "low",
            "output_labels": "INTERNAL",
            "approved": True,
            "approved_by": "admin",
        },
        {
            "server_id": "email-server",
            "server_fingerprint": "sha256:email-server-v1",
            "tool_name": "send_email",
            "tool_version": "1.0.0",
            "description_hash": compute_hash("Send email to a recipient"),
            "input_schema_hash": compute_hash({"to": "str", "subject": "str", "body": "str"}),
            "output_schema_hash": compute_hash({"status": "str"}),
            "capability_hash": compute_hash("write:email:external"),
            "risk_level": "medium",
            "output_labels": "EXTERNAL",
            "approved": True,
            "approved_by": "admin",
        },
        {
            "server_id": "finance-server",
            "server_fingerprint": "sha256:finance-server-v1",
            "tool_name": "transfer_funds",
            "tool_version": "1.0.0",
            "description_hash": compute_hash("Transfer funds between accounts"),
            "input_schema_hash": compute_hash({"to": "str", "amount": "float"}),
            "output_schema_hash": compute_hash({"status": "str"}),
            "capability_hash": compute_hash("write:funds"),
            "risk_level": "high",
            "output_labels": "FINANCIAL",
            "approved": True,
            "approved_by": "admin",
        },
    ]
    for t in tools:
        _upsert(db, t)