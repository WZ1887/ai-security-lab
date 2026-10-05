"""Ollama 嵌入客户端。

带磁盘持久化缓存：
  - 缓存路径：backend/.cache/embeddings.json
  - key = sha256(model + text)
  - value = embedding 向量
  - 首次跑完保存到磁盘，下次进程直接读
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

import httpx

from app.main import settings


# 缓存文件位置：backend/.cache/embeddings.json
_CACHE_DIR = Path(__file__).resolve().parents[3] / ".cache"
_CACHE_FILE = _CACHE_DIR / "embeddings.json"

_cache: dict[str, list[float]] = {}
_loaded = False


def _key(model: str, text: str) -> str:
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    h.update(b"\x00")
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def _load_cache() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    if not _CACHE_FILE.exists():
        return
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _cache.update(data)
    except Exception:
        pass


def _save_cache() -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
    except Exception:
        pass


def embed(text: str, timeout: float = 60.0) -> list[float]:
    _load_cache()

    model = settings.ollama_embed
    k = _key(model, text)
    if k in _cache:
        return _cache[k]

    with httpx.Client(trust_env=False, timeout=timeout) as client:
        r = client.post(
            f"{settings.ollama_host}/api/embeddings",
            json={"model": model, "prompt": text},
        )
    r.raise_for_status()
    vec = r.json()["embedding"]
    _cache[k] = vec
    _save_cache()
    return vec


def embed_many(texts: Iterable[str], timeout: float = 60.0) -> list[list[float]]:
    return [embed(t, timeout=timeout) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def cache_stats() -> dict:
    _load_cache()
    return {
        "cache_file": str(_CACHE_FILE),
        "entries": len(_cache),
    }