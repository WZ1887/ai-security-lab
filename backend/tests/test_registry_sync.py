"""工具注册表单源化回归测试。

不需要 Postgres / Redis / Ollama：只验证从 ToolSpec 派生的元数据。
"""

from app.mcp_guard.registry.sync import build_registry_rows, build_tool_index


def test_registry_rows_cover_all_tools():
    rows = build_registry_rows()
    assert {r["tool_name"] for r in rows} == {
        "get_order",
        "save_memory",
        "search_knowledge",
        "send_email",
        "transfer_funds",
    }
    for row in rows:
        assert row["approved"] is True
        assert row["approved_at"] is not None
        assert row["server_fingerprint"].startswith("sha256:")
        for key in (
            "description_hash",
            "input_schema_hash",
            "output_schema_hash",
            "capability_hash",
        ):
            assert row[key].startswith("sha256:")


def test_tool_index_matches_registry_hashes():
    """调用侧哈希必须与注册表一致，否则 G3 会拒掉所有工具调用。"""
    index = build_tool_index()
    rows = build_registry_rows()

    assert set(index) == {r["tool_name"] for r in rows}
    for row in rows:
        meta = index[row["tool_name"]]
        assert meta["server_id"] == row["server_id"]
        assert meta["tool_version"] == row["tool_version"]
        assert meta["description_hash"] == row["description_hash"]
        assert meta["input_schema_hash"] == row["input_schema_hash"]
        assert meta["capability_hash"] == row["capability_hash"]
        assert callable(meta["executor"])


def test_schema_drift_regression():
    """search_knowledge 的 schema 曾经在三处不一致，这里钉住真实值。"""
    meta = build_tool_index()["search_knowledge"]
    assert meta["input_schema"] == {"query": "str", "include_evil": "bool"}
