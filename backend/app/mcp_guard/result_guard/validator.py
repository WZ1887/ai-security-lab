"""工具结果校验。

工具返回数据一律视为不可信数据（DATA，不是 INSTRUCTION）。
检测：
  - 是否含注入指令
  - 数据标签（PII、FINANCIAL 等）
  - 长度上限
"""

import re
import time
from dataclasses import dataclass, field


# 结果中出现的可疑指令模式
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"忽略(之前|以上|所有).{0,6}(指令|规则)"),
    re.compile(r"SYSTEM\s*:", re.I),
    re.compile(r"<\|?system\|?>", re.I),
    re.compile(r"you\s+are\s+now\s+(in\s+)?developer\s+mode", re.I),
]

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


@dataclass
class ResultGuardOutput:
    safe: bool
    reason: str
    labels: list[str] = field(default_factory=list)
    risk_score: float = 0.0
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

    # 2. 注入指令检测
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            return ResultGuardOutput(
                safe=False,
                reason="RESULT_INSTRUCTION_DETECTED",
                labels=["INJECTION"],
                risk_score=0.9,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )

    # 3. PII 标签
    labels: list[str] = []
    if any(p.search(text) for p in PII_PATTERNS):
        labels.append("PII")

    # 4. 工具自身声明的输出标签（这里简化：按工具名推断）
    if inp.tool_name in ("get_order",):
        labels.append("ORDER_DATA")
    if inp.tool_name in ("transfer_funds",):
        labels.append("FINANCIAL")

    return ResultGuardOutput(
        safe=True,
        reason="OK",
        labels=list(dict.fromkeys(labels)),
        risk_score=0.0,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )
