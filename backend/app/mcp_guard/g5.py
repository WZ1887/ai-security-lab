"""G5 Approval + Execution + Result Validation Gate。

流程：
  PolicyOutput → [是否需要审批] → Sandbox 执行 → Result Guard → 输出
"""

import time
from dataclasses import dataclass, field
from typing import Callable

from app.mcp_guard.approval import store as approval_store
from app.mcp_guard.approval.tokens import verify as verify_token
from app.mcp_guard.result_guard.validator import (
    ResultGuardInput,
    validate as validate_result,
)
from app.mcp_guard.sandbox.executor import (
    SandboxInput,
    execute as sandbox_execute,
)


@dataclass
class ExecutionInput:
    session_id: str
    tool_name: str
    tool_arguments: dict
    requested_by: str
    policy_decision: str            # ALLOW / DENY / REQUIRE_APPROVAL
    policy_reason: str
    approval_token: str | None = None
    executor: Callable[[str, dict], dict] | None = None


@dataclass
class ExecutionOutput:
    success: bool
    reason: str
    result: dict = field(default_factory=dict)
    result_labels: list[str] = field(default_factory=list)
    result_risk: float = 0.0
    approval_verified: bool = False
    elapsed_ms: int = 0


def _fail(reason: str, start: float) -> ExecutionOutput:
    return ExecutionOutput(
        success=False,
        reason=reason,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )


def run(inp: ExecutionInput) -> ExecutionOutput:
    start = time.perf_counter()

    # 1. Policy 已拒
    if inp.policy_decision == "DENY":
        return _fail(f"POLICY_DENY:{inp.policy_reason}", start)

    # 2. 需要审批 → 校验令牌
    approval_verified = False
    if inp.policy_decision == "REQUIRE_APPROVAL":
        if not inp.approval_token:
            return _fail("APPROVAL_REQUIRED", start)

        vr = verify_token(
            token=inp.approval_token,
            expected_action=inp.tool_name,
            requester_id=inp.requested_by,
        )
        if not vr.valid:
            return _fail(f"APPROVAL_INVALID:{vr.reason}", start)

        # 防重放
        jti = (vr.payload or {}).get("jti", "")
        if approval_store.is_jti_used(jti):
            return _fail("APPROVAL_REPLAY", start)
        approval_store.mark_jti_used(jti)
        approval_verified = True

    # 3. 沙箱执行
    sb = sandbox_execute(
        SandboxInput(
            tool_name=inp.tool_name,
            arguments=inp.tool_arguments,
            executor=inp.executor,
        )
    )
    if not sb.success:
        return _fail(f"SANDBOX_FAIL:{sb.reason}", start)

    # 4. Result Guard
    rg = validate_result(
        ResultGuardInput(
            tool_name=inp.tool_name,
            raw_result=sb.result,
        )
    )
    if not rg.safe:
        return ExecutionOutput(
            success=False,
            reason=f"RESULT_GUARD_FAIL:{rg.reason}",
            result_labels=rg.labels,
            result_risk=rg.risk_score,
            approval_verified=approval_verified,
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )

    return ExecutionOutput(
        success=True,
        reason="OK",
        result=sb.result,
        result_labels=rg.labels,
        result_risk=rg.risk_score,
        approval_verified=approval_verified,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )