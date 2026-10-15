"""G3 工具信任：元数据哈希、Server 指纹、参数 schema。

用内存 SQLite，不需要 Postgres / Ollama。
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.mcp_guard.registry.g3 import ToolCallInput, validate
from app.mcp_guard.registry.sync import build_tool_index, sync_from_servers
from app.models import approval, audit_event, policy_rule, tool_registry, user  # noqa: F401
from app.models.base import Base


def _session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    sync_from_servers(db)
    return db


def _call(db, tool_name="get_order", arguments=None, **overrides):
    meta = build_tool_index()[tool_name]
    kwargs = {
        "server_id": meta["server_id"],
        "server_fingerprint": meta["server_fingerprint"],
        "tool_name": tool_name,
        "tool_version": meta["tool_version"],
        "input_schema_hash": meta["input_schema_hash"],
        "description_hash": meta["description_hash"],
        "capability_hash": meta["capability_hash"],
        "output_schema_hash": meta["output_schema_hash"],
        "input_schema": meta["input_schema"],
        "arguments": {"order_id": "10023"} if arguments is None else arguments,
    }
    kwargs.update(overrides)
    return validate(db, ToolCallInput(**kwargs))


def test_valid_call_passes_and_reports_registry_labels():
    out = _call(_session())
    assert out.valid
    assert out.reason == "OK"
    assert out.tool_risk_level == "low"
    assert out.output_labels == ["PII", "ORDER_DATA"]


def test_fake_server_fingerprint_rejected():
    """P7：冒充合法 Server 调用。"""
    out = _call(_session(), server_fingerprint="sha256:evil-server")
    assert not out.valid
    assert out.reason == "SERVER_FINGERPRINT_MISMATCH"


def test_output_schema_hash_mismatch_rejected():
    out = _call(_session(), output_schema_hash="sha256:deadbeef")
    assert not out.valid
    assert out.reason == "OUTPUT_SCHEMA_HASH_MISMATCH"


def test_caller_supplied_schema_must_match_registry():
    """调用方自带一份宽松 schema 会被哈希校验挡住。"""
    out = _call(_session(), input_schema={"order_id": "str", "admin": "str"})
    assert not out.valid
    assert out.reason == "INPUT_SCHEMA_HASH_MISMATCH"


def test_unknown_argument_rejected():
    out = _call(_session(), arguments={"order_id": "10023", "admin": "true"})
    assert not out.valid
    assert out.reason == "INVALID_ARGUMENTS:UNKNOWN_ARG:admin"


def test_numeric_string_is_coerced():
    out = _call(
        _session(),
        tool_name="transfer_funds",
        arguments={"to": "B", "amount": "1000"},
    )
    assert out.valid
    assert out.validated_args["amount"] == 1000.0


def test_type_mismatch_rejected():
    out = _call(
        _session(),
        tool_name="transfer_funds",
        arguments={"to": "B", "amount": "abc"},
    )
    assert not out.valid
    assert out.reason == "INVALID_ARGUMENTS:TYPE_MISMATCH:amount"
