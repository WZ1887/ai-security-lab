"""数据标签与 Sink 类型定义。"""

# 数据标签
PUBLIC = "PUBLIC"
INTERNAL = "INTERNAL"
PII = "PII"
FINANCIAL = "FINANCIAL"
SECRET = "SECRET"
TENANT_PRIVATE = "TENANT_PRIVATE"

ALL_LABELS = {PUBLIC, INTERNAL, PII, FINANCIAL, SECRET, TENANT_PRIVATE}

# Sink 类型
SINK_INTERNAL = "INTERNAL"
SINK_EXTERNAL = "EXTERNAL"

ALL_SINKS = {SINK_INTERNAL, SINK_EXTERNAL}

# 工具 → Sink 类型映射（后续可入库）
TOOL_SINK: dict[str, str] = {
    "get_order": SINK_INTERNAL,
    "search_knowledge": SINK_INTERNAL,
    "send_email": SINK_EXTERNAL,
    "transfer_funds": SINK_EXTERNAL,
    "read_file": SINK_INTERNAL,
}


def get_sink_type(tool_name: str) -> str:
    return TOOL_SINK.get(tool_name, SINK_INTERNAL)