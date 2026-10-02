from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    approval_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # 关联的会话与工具调用
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)

    # 发起人（Agent 或用户）
    requested_by: Mapped[str] = mapped_column(String(64), index=True)

    # 操作类型：TRANSFER_FUNDS / APPROVE_REFUND / UPDATE_ADDRESS / SEND_EMAIL_PII
    action: Mapped[str] = mapped_column(String(64), index=True)

    # 结构化展示内容（JSON）
    action_payload: Mapped[str] = mapped_column(Text, nullable=False)

    # 状态：pending / approved / rejected / expired
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)

    # 审批人（必须 ≠ requested_by）
    approver_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 第二审批人（双人复核）
    second_approver_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    second_approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 审批令牌
    approval_token_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 独立通道验证码（防钓鱼）
    verification_code_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_code_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )