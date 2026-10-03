"""G3 Tool Trust / Schema Gate。

校验工具身份、版本、Schema 哈希、描述哈希、能力哈希。
拦截工具投毒、工具重定义、Server 冒充。
纯计算 + 数据库查询，不依赖模型。
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy.orm import Session

from app.models.tool_registry import ToolRegistry


ToolRiskLevel = Literal["low", "medium", "high"]


@dataclass
class ToolCallInput:
    server_id: str
    tool_name: str
    tool_version: str
    input_schema_hash: str
    description_hash: str
    capability_hash: str
    arguments: dict
    session_token: str | None = None


@dataclass
class ToolTrustOutput:
    valid: bool
    reason: str
    validated_args: dict = field(default_factory=dict)
    tool_risk_level: ToolRiskLevel = "medium"
    output_labels: list[str] = field(default_factory=list)
    elapsed_ms: int = 0


def compute_hash(obj) -> str:
    if isinstance(obj, str):
        data = obj.encode("utf-8")
    else:
        data = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _lookup(db: Session, server_id: str, tool_name: str) -> ToolRegistry | None:
    return (
        db.query(ToolRegistry)
        .filter(ToolRegistry.server_id == server_id)
        .filter(ToolRegistry.tool_name == tool_name)
        .first()
    )


def _fail(reason: str, start: float, risk: ToolRiskLevel = "medium") -> ToolTrustOutput:
    return ToolTrustOutput(
        valid=False,
        reason=reason,
        tool_risk_level=risk,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )


def validate(db: Session, inp: ToolCallInput) -> ToolTrustOutput:
    start = time.perf_counter()

    tool = _lookup(db, inp.server_id, inp.tool_name)
    if tool is None:
        return _fail("TOOL_NOT_FOUND", start)

    risk: ToolRiskLevel = tool.risk_level  # type: ignore

    if not tool.approved:
        return _fail("TOOL_NOT_APPROVED", start, risk)

    if tool.tool_version != inp.tool_version:
        return _fail("TOOL_VERSION_MISMATCH", start, risk)

    if tool.input_schema_hash != inp.input_schema_hash:
        return _fail("INPUT_SCHEMA_HASH_MISMATCH", start, risk)

    if tool.description_hash != inp.description_hash:
        return _fail("DESCRIPTION_HASH_MISMATCH", start, risk)

    if tool.capability_hash != inp.capability_hash:
        return _fail("CAPABILITY_HASH_MISMATCH", start, risk)

    if not isinstance(inp.arguments, dict):
        return _fail("INVALID_ARGUMENTS_TYPE", start, risk)

    output_labels = [s for s in (tool.output_labels or "").split(",") if s]

    return ToolTrustOutput(
        valid=True,
        reason="OK",
        validated_args=inp.arguments,
        tool_risk_level=risk,
        output_labels=output_labels,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )