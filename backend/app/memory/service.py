"""记忆存储。

一个 MCP Server 自己持有存储：默认用全局 SessionLocal，
测试可以用 set_session_factory 注入临时库。
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.memory import guard
from app.models.memory import MemoryEntry


_session_factory: sessionmaker | None = None


def _default_factory() -> sessionmaker:
    from app.models.db import SessionLocal

    return SessionLocal


def set_session_factory(factory: sessionmaker | None) -> None:
    """测试用：把记忆存储指向临时库。"""
    global _session_factory
    _session_factory = factory


def _open() -> Session:
    factory = _session_factory or _default_factory()
    return factory()


def _hash(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def remember(
    *,
    tenant_id: str,
    user_id: str,
    session_id: str,
    content: str,
    declared_kind: str | None = None,
    source: str = "user",
) -> tuple[MemoryEntry | None, str]:
    """写入一条记忆。返回 (entry, reason)；被规则拒绝时 entry 为 None。"""
    verdict = guard.classify(content, declared_kind)
    if not verdict.allowed:
        return None, verdict.reason

    db = _open()
    try:
        entry = MemoryEntry(
            memory_id=str(uuid.uuid4()),
            tenant_id=tenant_id or "unknown",
            user_id=user_id or "unknown",
            session_id=session_id or "",
            kind=verdict.kind,
            content=verdict.normalized,
            content_hash=_hash(verdict.normalized),
            source=source,
            status="active",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry, "OK"
    finally:
        db.close()


def recall(
    *,
    tenant_id: str,
    user_id: str,
    limit: int | None = None,
) -> tuple[list[MemoryEntry], list[str]]:
    """取回该用户的记忆，返回 (可用记忆, 被隔离的原因)。

    读取侧重新分类：发现策略类内容就地隔离（防历史脏数据 / 旁路写入），
    并把隔离原因回传给调用方，便于审计与排查。
    """
    db = _open()
    try:
        entries = (
            db.query(MemoryEntry)
            .filter(MemoryEntry.tenant_id == tenant_id)
            .filter(MemoryEntry.user_id == user_id)
            .filter(MemoryEntry.status == "active")
            .order_by(MemoryEntry.id.desc())
            .limit(limit or settings.memory_recall_limit)
            .all()
        )

        safe: list[MemoryEntry] = []
        dropped: list[str] = []
        for entry in entries:
            verdict = guard.classify(entry.content, entry.kind)
            if verdict.allowed:
                safe.append(entry)
                continue
            # 读取侧兜底：历史脏数据 / 旁路写入的记忆在这里被隔离
            entry.status = "quarantined"
            entry.quarantine_reason = verdict.reason
            entry.updated_at = datetime.utcnow()
            dropped.append(verdict.reason)
        if dropped:
            db.commit()
        return safe, dropped
    finally:
        db.close()


def recall_for_prompt(
    *,
    tenant_id: str,
    user_id: str,
    limit: int | None = None,
) -> tuple[list[str], list[str]]:
    """给模型上下文用的安全事实列表，返回 (事实, 被丢弃的原因)。"""
    facts: list[str] = []
    entries, dropped = recall(tenant_id=tenant_id, user_id=user_id, limit=limit)
    for entry in entries:
        # 保底再查一次：这里放行才真正进模型上下文
        verdict = guard.classify(entry.content, entry.kind)
        if verdict.allowed:
            facts.append(verdict.normalized)
        else:
            dropped.append(verdict.reason)
    return facts, dropped


def forget(*, tenant_id: str, user_id: str, memory_id: str) -> bool:
    db = _open()
    try:
        entry = (
            db.query(MemoryEntry)
            .filter(MemoryEntry.memory_id == memory_id)
            .filter(MemoryEntry.tenant_id == tenant_id)
            .filter(MemoryEntry.user_id == user_id)
            .first()
        )
        if entry is None:
            return False
        entry.status = "deleted"
        entry.updated_at = datetime.utcnow()
        db.commit()
        return True
    finally:
        db.close()


def list_for_user(*, tenant_id: str, user_id: str, limit: int = 50) -> list[MemoryEntry]:
    """列出用户的记忆：软删除的不再返回，被隔离的仍然返回（便于用户看到发生了什么）。"""
    db = _open()
    try:
        return (
            db.query(MemoryEntry)
            .filter(MemoryEntry.tenant_id == tenant_id)
            .filter(MemoryEntry.user_id == user_id)
            .filter(MemoryEntry.status != "deleted")
            .order_by(MemoryEntry.id.desc())
            .limit(limit)
            .all()
        )
    finally:
        db.close()
