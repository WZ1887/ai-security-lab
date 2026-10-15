"""记忆接口：用户查看 / 删除自己的长期记忆。

记忆按 (tenant, user) 归属，key 用令牌里的 resource_user_id：
客服只能看到自己被授权代理的那个客户的记忆。
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.memory import service as memory_service
from app.security.principal import Principal, get_principal


router = APIRouter(prefix="/api/memory", tags=["memory"])


class MemoryItem(BaseModel):
    memory_id: str
    kind: str
    content: str
    status: str
    session_id: str = ""
    quarantine_reason: str | None = None
    created_at: datetime | None = None


class MemoryListResponse(BaseModel):
    total: int
    items: list[MemoryItem] = Field(default_factory=list)


class StatusResponse(BaseModel):
    status: str = "ok"
    detail: str = ""


def _to_item(entry) -> MemoryItem:
    return MemoryItem(
        memory_id=entry.memory_id,
        kind=entry.kind,
        content=entry.content,
        status=entry.status,
        session_id=entry.session_id or "",
        quarantine_reason=entry.quarantine_reason,
        created_at=entry.created_at,
    )


@router.get("", response_model=MemoryListResponse)
def list_memory(principal: Principal = Depends(get_principal)) -> MemoryListResponse:
    rows = memory_service.list_for_user(
        tenant_id=principal.tenant_id,
        user_id=principal.resource_user_id,
    )
    return MemoryListResponse(total=len(rows), items=[_to_item(r) for r in rows])


@router.delete("/{memory_id}", response_model=StatusResponse)
def forget_memory(
    memory_id: str,
    principal: Principal = Depends(get_principal),
) -> StatusResponse:
    ok = memory_service.forget(
        tenant_id=principal.tenant_id,
        user_id=principal.resource_user_id,
        memory_id=memory_id,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="MEMORY_NOT_FOUND")
    return StatusResponse(detail="MEMORY_DELETED")
