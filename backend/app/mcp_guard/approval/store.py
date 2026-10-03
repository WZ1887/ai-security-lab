"""审批记录存储：内存 + jti 防重放。

为了跑通 MVP，先用内存存储。
后续可替换为 approvals 表 + Redis。
"""

import time
from dataclasses import dataclass, field


@dataclass
class ApprovalRecord:
    approval_id: str
    session_id: str
    action: str
    requested_by: str
    action_payload: dict
    status: str = "pending"
    approver_id: str | None = None
    token_jti: str | None = None
    created_at: float = field(default_factory=time.time)


_records: dict[str, ApprovalRecord] = {}
_used_jti: set[str] = set()


def create(
    approval_id: str,
    session_id: str,
    action: str,
    requested_by: str,
    action_payload: dict,
) -> ApprovalRecord:
    rec = ApprovalRecord(
        approval_id=approval_id,
        session_id=session_id,
        action=action,
        requested_by=requested_by,
        action_payload=action_payload,
    )
    _records[approval_id] = rec
    return rec


def get(approval_id: str) -> ApprovalRecord | None:
    return _records.get(approval_id)


def approve(approval_id: str, approver_id: str, jti: str) -> ApprovalRecord | None:
    rec = _records.get(approval_id)
    if rec is None:
        return None
    if rec.status != "pending":
        return rec
    rec.status = "approved"
    rec.approver_id = approver_id
    rec.token_jti = jti
    return rec


def is_jti_used(jti: str) -> bool:
    return jti in _used_jti


def mark_jti_used(jti: str) -> None:
    _used_jti.add(jti)


def reset_for_test() -> None:
    _records.clear()
    _used_jti.clear()