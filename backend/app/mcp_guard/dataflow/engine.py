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
    SECRET,
    SINK_EXTERNAL,
    SINK_INTERNAL,
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


def evaluate(source_labels: list[str], sink_type: str) -> DataFlowDecision:
    # SECRET → 任何 sink 都拒
    if SECRET in source_labels:
        return DataFlowDecision(
            action="DENY",
            reason="SECRET_DATA_FLOW",
            rule_id="DF-100",
        )

    # DENY 规则优先
    for label in source_labels:
        key = (label, sink_type)
        if key in _DENY_RULES:
            reason, rule_id = _DENY_RULES[key]
            return DataFlowDecision(action="DENY", reason=reason, rule_id=rule_id)

    # 再检查审批规则
    for label in source_labels:
        key = (label, sink_type)
        if key in _APPROVAL_RULES:
            reason, rule_id = _APPROVAL_RULES[key]
            return DataFlowDecision(
                action="REQUIRE_APPROVAL", reason=reason, rule_id=rule_id
            )

    return DataFlowDecision(action="ALLOW", reason="OK", rule_id="DF-000")