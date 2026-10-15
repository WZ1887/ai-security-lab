"""工具结果校验。

工具返回数据一律视为不可信数据（DATA，不是 INSTRUCTION）。
检测：
  - 是否含注入指令（先过 G1 规范化，否则零宽 / 全角 / URL 编码写法能绕过正则）
  - 数据标签（PII、FINANCIAL 等）
  - 长度上限
"""

import re
import time
from dataclasses import dataclass, field

from app.mcp_guard.canonicalize.g1 import CanonicalizeInput, canonicalize
from app.mcp_guard.untrusted import INJECTION_PATTERNS, POLICY_PATTERNS


# 简单 PII 检测
PII_PATTERNS = [
    re.compile(r"\b1[3-9]\d{9}\b"),                          # 中国手机号
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),             # 邮箱
    re.compile(r"\b\d{17}[\dXx]\b"),                         # 身份证
]

MAX_RESULT_BYTES = 65536


@dataclass
class ResultGuardInput:
    tool_name: str
    raw_result: str | dict
    # 工具声明的输出标签（来自 tool_registry，避免按工具名硬编码第二份）
    declared_labels: list[str] = field(default_factory=list)


@dataclass
class ResultGuardOutput:
    safe: bool
    reason: str
    labels: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    transformations: list[str] = field(default_factory=list)
    elapsed_ms: int = 0


def _to_text(raw) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        return " ".join(f"{k}={v}" for k, v in raw.items())
    return str(raw)


def validate(inp: ResultGuardInput) -> ResultGuardOutput:
    start = time.perf_counter()

    text = _to_text(inp.raw_result)

    # 1. 长度
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        return ResultGuardOutput(
            safe=False,
            reason="RESULT_TOO_LARGE",
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )

    # 2. 结果同样是不可信输入：先规范化再匹配指令模式
    canon = canonicalize(CanonicalizeInput(raw_text=text, source="tool_result"))
    scan_text = canon.normalized_text
    transformations = canon.transformations

    # 3. 注入指令检测（在规范化后的文本上）
    for pat in INJECTION_PATTERNS:
        if pat.search(scan_text):
            return ResultGuardOutput(
                safe=False,
                reason="RESULT_INSTRUCTION_DETECTED",
                labels=["INJECTION"],
                risk_score=0.9,
                transformations=transformations,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )

    # 3b. 策略/权限类声明同样不该出现在工具结果里：
    #     它是"数据"，但一旦被当成规则读进去，就等于让数据改了策略
    for pat in POLICY_PATTERNS:
        if pat.search(scan_text):
            return ResultGuardOutput(
                safe=False,
                reason="RESULT_POLICY_CLAIM_DETECTED",
                labels=["POLICY_CLAIM"],
                risk_score=0.9,
                transformations=transformations,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )

    # 4. 标签：内容级检测（PII）+ 工具声明（注册表）
    labels: list[str] = list(inp.declared_labels)
    if any(p.search(scan_text) for p in PII_PATTERNS) and "PII" not in labels:
        labels.append("PII")

    # 5. 工具自身返回的错误（例如归属校验把越权伪装成 not_found）也打标，
    #    这样审计里能检索到，而对外响应不变、不泄露“存在但不属于你”
    if isinstance(inp.raw_result, dict) and inp.raw_result.get("error"):
        labels.append("TOOL_ERROR")

    return ResultGuardOutput(
        safe=True,
        reason="OK",
        labels=list(dict.fromkeys(labels)),
        risk_score=0.0,
        transformations=transformations,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )
