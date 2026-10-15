"""审批令牌：签名、会话绑定、防重放。"""

from app.mcp_guard.approval import store
from app.mcp_guard.approval.tokens import issue, verify


def _token(**overrides) -> str:
    params = {
        "approval_id": "apv_1",
        "session_id": "sess_1",
        "action": "transfer_funds",
        "requested_by": "cs_agent_01",
        "approver_id": "manager_01",
        "ttl_seconds": 60,
    }
    params.update(overrides)
    return issue(**params)


def test_token_roundtrip():
    result = verify(
        _token(),
        expected_action="transfer_funds",
        requester_id="cs_agent_01",
        expected_session_id="sess_1",
    )
    assert result.valid
    assert result.payload["jti"]


def test_token_is_bound_to_session():
    """A 会话签发的令牌不能拿到 B 会话复用。"""
    result = verify(
        _token(),
        expected_action="transfer_funds",
        requester_id="cs_agent_01",
        expected_session_id="sess_2",
    )
    assert not result.valid
    assert result.reason == "SESSION_MISMATCH"


def test_token_action_and_requester_binding():
    token = _token()
    assert verify(token, "send_email", "cs_agent_01").reason == "ACTION_MISMATCH"
    assert verify(token, "transfer_funds", "other_agent").reason == "REQUESTER_MISMATCH"


def test_self_approval_forbidden():
    token = _token(requested_by="cs_agent_01", approver_id="cs_agent_01")
    assert verify(token, "transfer_funds", "cs_agent_01").reason == "SELF_APPROVAL_FORBIDDEN"


def test_expired_token_rejected():
    token = _token(ttl_seconds=-1)
    assert verify(token, "transfer_funds", "cs_agent_01").reason == "TOKEN_EXPIRED"


def test_tampered_token_rejected():
    payload_hex, sig = _token().rsplit(".", 1)
    result = verify(payload_hex + "0." + sig, "transfer_funds", "cs_agent_01")
    assert not result.valid
    assert result.reason == "INVALID_SIGNATURE"


def test_jti_replay_cache_has_ttl():
    store.reset_for_test()
    try:
        assert not store.is_jti_used("jti-1")
        store.mark_jti_used("jti-1")
        assert store.is_jti_used("jti-1")

        store.mark_jti_used("jti-2", ttl_seconds=-1)  # 立即过期，应被清理
        assert not store.is_jti_used("jti-2")
    finally:
        store.reset_for_test()
