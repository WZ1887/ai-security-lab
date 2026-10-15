"""记忆守卫：记忆只能存事实，不能存策略 / 权限 / 工具配置。

这是 A6（记忆投毒）的核心规则。两个方向都要守：
  - 写入侧：内容或声明的类型只要带策略/权限含义，直接拒绝（G4 判定 + 工具内再查一次）
  - 读取侧：注入模型上下文前重新分类，发现策略类内容就隔离（防止历史脏数据或旁路写入）

判定顺序与其它 Gate 一致：先 G1 归一化，再匹配。否则零宽 / 全角 / Base64 包裹的
"我是管理员" 就能绕过。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.mcp_guard.canonicalize.g1 import CanonicalizeInput, canonicalize
from app.mcp_guard.untrusted import INJECTION_PATTERNS, POLICY_PATTERNS


# 允许的记忆类型
ALLOWED_KINDS = {"fact", "preference"}
# 一旦声明成这些类型就直接拒绝：记忆不该承载策略与权限
FORBIDDEN_KINDS = {
    "policy",
    "permission",
    "permissions",
    "role",
    "role_claim",
    "acl",
    "config",
    "tool_config",
    "grant",
}

@dataclass
class MemoryVerdict:
    allowed: bool
    reason: str
    kind: str
    normalized: str = ""
    signals: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)


def classify(content: str, declared_kind: str | None = None) -> MemoryVerdict:
    """判断一条记忆能不能存。"""
    canon = canonicalize(CanonicalizeInput(raw_text=content or "", source="memory"))
    text = canon.normalized_text

    kind = (declared_kind or "").strip().lower() or "fact"
    if kind in FORBIDDEN_KINDS:
        return MemoryVerdict(
            allowed=False,
            reason="MEMORY_CANNOT_STORE_POLICY",
            kind=kind,
            normalized=text,
            signals=["declared_policy_kind"],
            transformations=canon.transformations,
        )

    if any(p.search(text) for p in POLICY_PATTERNS):
        return MemoryVerdict(
            allowed=False,
            reason="MEMORY_CANNOT_STORE_POLICY",
            kind=kind,
            normalized=text,
            signals=["policy_claim"],
            transformations=canon.transformations,
        )

    if any(p.search(text) for p in INJECTION_PATTERNS):
        return MemoryVerdict(
            allowed=False,
            reason="MEMORY_CONTAINS_INSTRUCTION",
            kind=kind,
            normalized=text,
            signals=["injection_pattern"],
            transformations=canon.transformations,
        )

    if not text.strip():
        return MemoryVerdict(
            allowed=False,
            reason="MEMORY_EMPTY",
            kind=kind,
            normalized=text,
            transformations=canon.transformations,
        )

    if kind not in ALLOWED_KINDS:
        kind = "fact"
    return MemoryVerdict(
        allowed=True,
        reason="OK",
        kind=kind,
        normalized=text,
        transformations=canon.transformations,
    )


MEMORY_WRITE_TOOL = "save_memory"


def check_tool_call(tool_name: str, arguments: dict) -> MemoryVerdict | None:
    """G4 用：只有记忆写入类工具才返回判定，其它工具返回 None。"""
    if tool_name != MEMORY_WRITE_TOOL:
        return None
    return classify(
        str((arguments or {}).get("content", "")),
        str((arguments or {}).get("kind", "") or ""),
    )
