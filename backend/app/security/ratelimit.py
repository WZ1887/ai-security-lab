"""进程内固定窗口限流（单实例）。

用于自注册这类“不需要先认证”的接口。多实例部署需要换成 Redis 之类的共享计数。
"""

from __future__ import annotations

import threading
import time


_buckets: dict[str, tuple[float, int]] = {}
_lock = threading.Lock()


def hit(key: str, limit: int, window_seconds: int) -> bool:
    """记一次访问；返回 True 表示允许（未超限）。"""
    now = time.time()
    with _lock:
        # 顺手清理过期窗口，避免无界增长
        for k in [k for k, (start, _) in _buckets.items() if now - start >= window_seconds]:
            _buckets.pop(k, None)

        start, count = _buckets.get(key, (now, 0))
        if now - start >= window_seconds:
            start, count = now, 0
        count += 1
        _buckets[key] = (start, count)
        return count <= limit


def reset_for_test() -> None:
    with _lock:
        _buckets.clear()
