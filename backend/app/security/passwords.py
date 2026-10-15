"""口令哈希。

- 用 bcrypt（backend/requirements.txt 已声明，可直接验证）
- 先 sha256 + base64 预哈希再交给 bcrypt：绕开 bcrypt 的 72 字节截断，
  否则“前 72 字节相同的两个密码”会被判成同一个密码
- 校验失败一律返回 False，调用方不区分“用户不存在 / 密码错误”
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt


BCRYPT_ROUNDS = 12


def _prehash(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("ascii"))
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    """成本参数变了就顺手升级（登录成功后调用）。"""
    try:
        # bcrypt 格式：$2b$<rounds>$<salt+hash>
        rounds = int(password_hash.split("$")[2])
    except Exception:
        return True
    return rounds != BCRYPT_ROUNDS
