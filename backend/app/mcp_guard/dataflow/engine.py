"""数据流策略引擎。

规则：
  PII          → EXTERNAL   DENY
  FINANCIAL    → EXTERNAL   DENY
  SECRET       → ANY        DENY
  INTERNAL     → EXTERNAL   REQUIRE_APPROVAL
  其他                        ALLOW
"""

from dataclasses import dataclass

from app.mcp_guard.dataflow.labels import (
    FINANCIAL,
    INTERNAL,
    PII,
    PUBLIC,
    SECRET,
    SINK_EXTERNAL,
    SINK_INTERNAL,
    TENANT_PRIVATE,
)


@dataclass
class DataFlowDecision:
    action: str          # ALLOW / DENY / REQUIRE_APPROVAL
    reason: str          # OK / PII_TO_EXTERNAL / ...
    rule_id: str


_DENY_RULES = {
    (PII, SINK_EXTERNAL): ("PII_TO_EXTERNAL", "DF-001"),
    (FINANCIAL, SINK_EXTERNAL): ("FINANCIAL_TO_EXTERNAL", "DF-002"),
}

_APPROVAL_RULES = {
    (INTERNAL, SINK_EXTERNAL): ("INTERNAL_TO_EXTERNAL", "DF-003"),
}

# 命中多个标签时的判定顺序：按严重程度，而不是按传入顺序，
# 这样审计里的原因码是稳定可解释的（否则同一次违规可能报 PII 也可能报 FINANCIAL）。
_LABEL_PRIORITY = [SECRET, PII, FINANCIAL, TENANT_PRIVATE, INTERNAL, PUBLIC]


def _ordered_labels(labels: list[str]) -> list[str]:
    known = [label for label in _LABEL_PRIORITY if label in labels]
    unknown = [label for label in labels if label not in _LABEL_PRIORITY]
    return known + unknown


def evaluate(source_labels: list[str], sink_type: str) -> DataFlowDecision:
    ordered = _ordered_labels(list(source_labels))

    # SECRET → 任何 sink 都拒
    if SECRET in ordered:
        return DataFlowDecision(
            action="DENY",
            reason="SECRET_DATA_FLOW",
            rule_id="DF-100",
        )

    # DENY 规则优先
    for label in ordered:
        key = (label, sink_type)
        if key in _DENY_RULES:
            reason, rule_id = _DENY_RULES[key]
            return DataFlowDecision(action="DENY", reason=reason, rule_id=rule_id)

    # 再检查审批规则
    for label in ordered:
        key = (label, sink_type)
        if key in _APPROVAL_RULES:
            reason, rule_id = _APPROVAL_RULES[key]
            return DataFlowDecision(
                action="REQUIRE_APPROVAL", reason=reason, rule_id=rule_id
            )

    return DataFlowDecision(action="ALLOW", reason="OK", rule_id="DF-000")
