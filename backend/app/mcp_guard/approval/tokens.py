"""审批令牌：签发与校验。

审批令牌用于确认高风险操作已被人为批准。
必须满足：
  - 签名有效
  - 未过期
  - jti 未被使用（防重放）
  - 审批人 ≠ 发起人
"""

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from app.config import settings


SECRET = settings.approval_token_secret.encode("utf-8")


@dataclass
class ApprovalToken:
    approval_id: str
    session_id: str
    action: str
    requested_by: str
    approver_id: str
    jti: str
    issued_at: int
    expires_at: int


@dataclass
class TokenVerifyResult:
    valid: bool
    reason: str
    payload: dict | None = None


def _b64(obj: dict) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return raw.hex()


def _sign(payload_hex: str) -> str:
    return hmac.new(SECRET, payload_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def issue(
    approval_id: str,
    session_id: str,
    action: str,
    requested_by: str,
    approver_id: str,
    ttl_seconds: int = 300,
) -> str:
    now = int(time.time())
    payload = {
        "approval_id": approval_id,
        "session_id": session_id,
        "action": action,
        "requested_by": requested_by,
        "approver_id": approver_id,
        "jti": str(uuid.uuid4()),
        "issued_at": now,
        "expires_at": now + ttl_seconds,
    }
    payload_hex = _b64(payload)
    sig = _sign(payload_hex)
    return f"{payload_hex}.{sig}"


def verify(
    token: str,
    expected_action: str,
    requester_id: str,
    expected_session_id: str | None = None,
) -> TokenVerifyResult:
    if not token or "." not in token:
        return TokenVerifyResult(False, "MALFORMED_TOKEN")

    payload_hex, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(_sign(payload_hex), sig):
        return TokenVerifyResult(False, "INVALID_SIGNATURE")

    try:
        payload = json.loads(bytes.fromhex(payload_hex).decode("utf-8"))
    except Exception:
        return TokenVerifyResult(False, "MALFORMED_PAYLOAD")

    now = int(time.time())
    if payload.get("expires_at", 0) < now:
        return TokenVerifyResult(False, "TOKEN_EXPIRED")

    if payload.get("action") != expected_action:
        return TokenVerifyResult(False, "ACTION_MISMATCH")

    if payload.get("requested_by") == payload.get("approver_id"):
        return TokenVerifyResult(False, "SELF_APPROVAL_FORBIDDEN")

    if payload.get("requested_by") != requester_id:
        return TokenVerifyResult(False, "REQUESTER_MISMATCH")

    # 令牌与会话绑定：A 会话签发的令牌不能拿到 B 会话复用
    if expected_session_id is not None and payload.get("session_id") != expected_session_id:
        return TokenVerifyResult(False, "SESSION_MISMATCH")

    return TokenVerifyResult(True, "OK", payload)


def decode_payload(token: str) -> dict:
    """取出 payload，不做签名校验（仅供签发方自己解析 jti / expires_at）。"""
    payload_hex, _, _ = token.rpartition(".")
    return json.loads(bytes.fromhex(payload_hex).decode("utf-8"))
