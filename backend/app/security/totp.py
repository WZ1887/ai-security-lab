"""TOTP（RFC 6238）——标准库实现，不引入额外依赖。

对齐 RFC 4226（HOTP）/ RFC 6238（TOTP），并用官方测试向量做回归
（见 tests/test_auth_login.py）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode


DEFAULT_DIGITS = 6
DEFAULT_INTERVAL = 30
DEFAULT_WINDOW = 1          # 允许 ±1 个时间步，容忍客户端时钟漂移
SECRET_BYTES = 20           # 160 bit


def generate_secret(length: int = SECRET_BYTES) -> str:
    """返回 base32 编码的随机密钥。"""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    normalized = secret.strip().replace(" ", "").upper()
    normalized += "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized, casefold=True)


def _hotp(secret: bytes, counter: int, digits: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def code_at(
    secret: str,
    timestamp: float,
    *,
    digits: int = DEFAULT_DIGITS,
    interval: int = DEFAULT_INTERVAL,
) -> str:
    """给定时刻的 TOTP 码（timestamp 为 Unix 秒）。"""
    return _hotp(_decode_secret(secret), int(timestamp // interval), digits)


def verify(
    code: str,
    secret: str,
    *,
    at_time: float | None = None,
    digits: int = DEFAULT_DIGITS,
    interval: int = DEFAULT_INTERVAL,
    window: int = DEFAULT_WINDOW,
) -> bool:
    if not code or not secret:
        return False
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit() or len(candidate) != digits:
        return False

    now = time.time() if at_time is None else at_time
    for offset in range(-window, window + 1):
        expected = code_at(secret, now + offset * interval, digits=digits, interval=interval)
        if hmac.compare_digest(expected, candidate):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """otpauth:// 链接，供 Authenticator 扫码录入。"""
    label = quote(f"{issuer}:{account}")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DEFAULT_DIGITS,
            "period": DEFAULT_INTERVAL,
        }
    )
    return f"otpauth://totp/{label}?{params}"
