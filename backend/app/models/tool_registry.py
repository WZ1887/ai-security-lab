from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class ToolRegistry(Base):
    __tablename__ = "tool_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    server_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    server_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)

    tool_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)

    description_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    input_schema_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    output_schema_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    capability_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    output_labels: Mapped[str] = mapped_column(String(255), default="")

    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )