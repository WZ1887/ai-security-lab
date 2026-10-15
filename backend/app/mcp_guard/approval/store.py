"""审批令牌 jti 防重放缓存。

MVP：进程内存 + TTL 懒清理，重启即失效。
多实例部署时应换成 Redis，或依赖 approvals.approval_token_jti 的唯一约束
（DB 版的审批记录在 approval/service.py）。
"""

import time

_DEFAULT_TTL_SECONDS = 3600

_used: dict[str, float] = {}


def _prune(now: float) -> None:
    for jti in [k for k, expires_at in _used.items() if expires_at <= now]:
        _used.pop(jti, None)


def is_jti_used(jti: str) -> bool:
    """令牌是否已被使用（顺带清理过期条目）。"""
    if not jti:
        return False
    _prune(time.time())
    return jti in _used


def mark_jti_used(jti: str, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
    """标记令牌已使用，ttl_seconds 后自动过期。"""
    if not jti:
        return
    _used[jti] = time.time() + ttl_seconds


def reset_for_test() -> None:
    _used.clear()
