"""Ollama 嵌入客户端。带简单内存缓存。"""

import hashlib
from typing import Iterable

import httpx

from app.main import settings


_cache: dict[str, list[float]] = {}


def _key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def embed(text: str, timeout: float = 10.0) -> list[float]:
    k = _key(text)
    if k in _cache:
        return _cache[k]

    with httpx.Client(trust_env=False, timeout=timeout) as client:
        r = client.post(
            f"{settings.ollama_host}/api/embeddings",
            json={"model": settings.ollama_embed, "prompt": text},
        )
    r.raise_for_status()
    vec = r.json()["embedding"]
    _cache[k] = vec
    return vec


def embed_many(texts: Iterable[str], timeout: float = 20.0) -> list[list[float]]:
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