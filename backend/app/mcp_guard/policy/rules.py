"""RBAC / ABAC 规则（先硬编码，后续可入库覆盖）。"""

# 角色 → 允许的工具集合
ROLE_TOOLS: dict[str, set[str]] = {
    "customer": set(),
    "cs_agent": {
        "get_order",
        "search_knowledge",
        "send_email",
        "update_address",
        "create_refund_request",
    },
    "finance_agent": {
        "get_order",
        "search_knowledge",
        "send_email",
        "create_refund_request",
        "approve_refund",
        "transfer_funds",
    },
    "admin": {"*"},
}

# 高风险工具：必须人工审批
HIGH_RISK_TOOLS: set[str] = {
    "transfer_funds",
    "approve_refund",
}

# 中风险工具：语义风险高时需审批
MEDIUM_RISK_TOOLS: set[str] = {
    "send_email",
    "update_address",
    "create_refund_request",
}


def role_allows_tool(roles: list[str], tool_name: str) -> bool:
    for r in roles:
        allowed = ROLE_TOOLS.get(r, set())
        if "*" in allowed or tool_name in allowed:
            return True
    return False
    