"""简化参数 schema 校验。

项目里的 schema 不是标准 JSON Schema，而是 {字段名: 类型名} 一张表
（与 MCP Server 的 ToolSpec.input_schema 一致）。这里做三件事：

  1. 拒绝未声明的字段——防参数走私 / 越权字段注入
  2. 校验已声明字段的类型
  3. 把 "1000" 这类数字字符串规范化成 float/int，避免下游 float() 直接炸

注意：本格式无法表达“必填 / 可选”，所以只做“不认识的字段一律拒绝”，
漏传字段交给工具自身处理（工具会返回参数错误）。
"""

from __future__ import annotations

from typing import Any


_TYPE_ALIASES = {
    "string": "str",
    "text": "str",
    "number": "float",
    "integer": "int",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
}


def _norm_type(name: Any) -> str:
    return _TYPE_ALIASES.get(str(name).lower(), str(name).lower())


def _coerce(value: Any, expected: str) -> tuple[Any, str | None]:
    """返回 (规范化后的值, 错误码或 None)。"""
    if expected in ("any", ""):
        return value, None

    if expected == "str":
        return (value, None) if isinstance(value, str) else (value, "TYPE_MISMATCH")

    if expected == "int":
        if isinstance(value, bool):
            return value, "TYPE_MISMATCH"
        if isinstance(value, int):
            return value, None
        if isinstance(value, str):
            try:
                return int(value.strip()), None
            except ValueError:
                return value, "TYPE_MISMATCH"
        return value, "TYPE_MISMATCH"

    if expected == "float":
        if isinstance(value, bool):
            return value, "TYPE_MISMATCH"
        if isinstance(value, (int, float)):
            return float(value), None
        if isinstance(value, str):
            try:
                return float(value.strip()), None
            except ValueError:
                return value, "TYPE_MISMATCH"
        return value, "TYPE_MISMATCH"

    if expected == "bool":
        if isinstance(value, bool):
            return value, None
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true", None
        return value, "TYPE_MISMATCH"

    if expected == "list":
        return (value, None) if isinstance(value, list) else (value, "TYPE_MISMATCH")

    if expected == "dict":
        return (value, None) if isinstance(value, dict) else (value, "TYPE_MISMATCH")

    # 未识别的类型名：保守放行，不因为 schema 写法陌生而误拦
    return value, None


def validate_arguments(
    schema: dict | None,
    arguments: dict,
) -> tuple[dict, list[str]]:
    """返回 (规范化后的参数, 问题列表)；问题非空即视为校验失败。"""
    if not isinstance(arguments, dict):
        return {}, ["ARGS_NOT_DICT"]

    schema = schema or {}
    problems: list[str] = []
    validated: dict = {}

    for key, value in arguments.items():
        if key not in schema:
            problems.append(f"UNKNOWN_ARG:{key}")
            continue
        coerced, err = _coerce(value, _norm_type(schema[key]))
        if err:
            problems.append(f"{err}:{key}")
            continue
        validated[key] = coerced

    return validated, problems
