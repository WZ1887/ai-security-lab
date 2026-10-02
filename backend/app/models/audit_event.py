from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Float, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    session_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    subject: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent: Mapped[str | None] = mapped_column(String(64), nullable=True)

    server_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    # 各 Gate 的结果（JSON 字符串）
    gate_results: Mapped[str | None] = mapped_column(Text, nullable=True)

    policy_action: Mapped[str] = mapped_column(String(32), index=True)
    policy_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)

    input_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tool_schema_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # hash chain
    prev_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)