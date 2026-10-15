"""审批接口：创建待审批单 / 人工批准签发令牌 / 查询。

身份全部来自认证令牌，请求体不再携带身份：
  - 发起人（requested_by）＝ 令牌里的 agent_id（回退 user_id）
  - 审批人（approver_id）＝ 调用批准接口的人，且必须持有审批角色
  - 租户隔离：只能查询 / 批准自己租户的单子
"""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.mcp_guard.approval import service as approval_service
from app.mcp_guard.approval import tokens
from app.mcp_guard.approval.service import ApprovalError
from app.models.db import get_db
from app.security.principal import Principal, get_principal
from app.security.roles import APPROVER_ROLES, require_approver_role  # noqa: F401


router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class CreateApprovalRequest(BaseModel):
    session_id: str
    action: str
    action_payload: dict = Field(default_factory=dict)


class ApprovalItem(BaseModel):
    approval_id: str
    session_id: str
    tenant_id: str
    action: str
    requested_by: str
    status: str
    approver_id: str | None = None
    action_payload: dict = Field(default_factory=dict)
    created_at: datetime | None = None
    approved_at: datetime | None = None
    token_expires_at: datetime | None = None


class ApproveResponse(BaseModel):
    approval_id: str
    status: str
    approval_token: str
    expires_at: int


def _to_item(rec) -> ApprovalItem:
    try:
        payload = json.loads(rec.action_payload or "{}")
    except Exception:
        payload = {}
    return ApprovalItem(
        approval_id=rec.approval_id,
        session_id=rec.session_id,
        tenant_id=rec.tenant_id,
        action=rec.action,
        requested_by=rec.requested_by,
        status=rec.status,
        approver_id=rec.approver_id,
        action_payload=payload if isinstance(payload, dict) else {},
        created_at=rec.created_at,
        approved_at=rec.approved_at,
        token_expires_at=rec.token_expires_at,
    )


def _http_error(exc: ApprovalError) -> HTTPException:
    status_code = 404 if exc.reason == "NOT_FOUND" else 409
    return HTTPException(status_code=status_code, detail=exc.reason)


@router.post("", response_model=ApprovalItem)
def create_approval(
    req: CreateApprovalRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ApprovalItem:
    rec = approval_service.create_pending(
        db,
        session_id=req.session_id,
        tenant_id=principal.tenant_id,
        action=req.action,
        requested_by=principal.agent_id or principal.user_id,
        action_payload=req.action_payload,
    )
    return _to_item(rec)


@router.get("", response_model=list[ApprovalItem])
def list_approvals(
    principal: Principal = Depends(get_principal),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[ApprovalItem]:
    return [
        _to_item(r)
        for r in approval_service.list_recent(db, limit, tenant_id=principal.tenant_id)
    ]


def _load_for_tenant(db: Session, approval_id: str, principal: Principal):
    """取审批单并校验租户归属；跨租户一律按不存在处理。"""
    rec = approval_service.get(db, approval_id)
    if rec is None or rec.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="NOT_FOUND")
    return rec


@router.get("/{approval_id}", response_model=ApprovalItem)
def get_approval(
    approval_id: str,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ApprovalItem:
    return _to_item(_load_for_tenant(db, approval_id, principal))


@router.post("/{approval_id}/approve", response_model=ApproveResponse)
def approve(
    approval_id: str,
    principal: Principal = Depends(require_approver_role),
    db: Session = Depends(get_db),
) -> ApproveResponse:
    _load_for_tenant(db, approval_id, principal)
    try:
        rec, token = approval_service.approve(
            db,
            approval_id=approval_id,
            approver_id=principal.user_id,
        )
    except ApprovalError as e:
        raise _http_error(e) from e

    payload = tokens.decode_payload(token)
    return ApproveResponse(
        approval_id=rec.approval_id,
        status=rec.status,
        approval_token=token,
        expires_at=payload["expires_at"],
    )


@router.post("/{approval_id}/reject", response_model=ApprovalItem)
def reject(
    approval_id: str,
    principal: Principal = Depends(require_approver_role),
    db: Session = Depends(get_db),
) -> ApprovalItem:
    _load_for_tenant(db, approval_id, principal)
    try:
        rec = approval_service.reject(
            db,
            approval_id=approval_id,
            approver_id=principal.user_id,
        )
    except ApprovalError as e:
        raise _http_error(e) from e
    return _to_item(rec)
