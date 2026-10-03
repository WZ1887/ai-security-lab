import base64
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Literal


# ---------- 输入 / 输出 ----------

SourceType = Literal["user", "tool_description", "tool_result", "memory", "document"]


@dataclass
class CanonicalizeInput:
    raw_text: str
    source: SourceType
    max_bytes: int = 65536
    max_decode_depth: int = 3
    max_expansion_ratio: float = 10.0
    timeout_ms: int = 50


@dataclass
class CanonicalizeOutput:
    normalized_text: str
    transformations: list[str] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)
    truncated: bool = False
    elapsed_ms: int = 0


# ---------- 常量 ----------

ZERO_WIDTH = [
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
]

URL_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
MD_PATTERN = re.compile(r"\*\*(.+?)\*\*|`(.+?)`|\[(.+?)\]\(.+?\)")


# ---------- 单步变换 ----------

def _strip_zero_width(text: str, transformations: list[str]) -> str:
    original = text
    for ch in ZERO_WIDTH:
        text = text.replace(ch, "")
    if text != original:
        transformations.append("zero_width_removed")
    return text


def _nfkc(text: str, transformations: list[str]) -> str:
    out = unicodedata.normalize("NFKC", text)
    if out != text:
        transformations.append("unicode_nfkc")
    return out


def _fullwidth_to_halfwidth(text: str, transformations: list[str]) -> str:
    out = []
    changed = False
    for ch in text:
        code = ord(ch)
        if 0xFF01 <= code <= 0xFF5E:
            out.append(chr(code - 0xFEE0))
            changed = True
        elif code == 0x3000:
            out.append(" ")
            changed = True
        else:
            out.append(ch)
    if changed:
        transformations.append("fullwidth_to_halfwidth")
    return "".join(out)


def _decode_url(text: str, depth: int, transformations: list[str]) -> str:
    d = 0
    while d < depth and URL_PATTERN.search(text):
        try:
            decoded = bytes(text, "utf-8").decode("unicode_escape")
        except Exception:
            break
        try:
            decoded = re.sub(
                r"%[0-9A-Fa-f]{2}",
                lambda m: bytes.fromhex(m.group(0)[1:]).decode("latin-1"),
                text,
            )
        except Exception:
            break
        if decoded == text:
            break
        text = decoded
        d += 1
        transformations.append("url_decoded")
    return text


def _decode_base64(text: str, depth: int, transformations: list[str]) -> str:
    d = 0
    current = text.strip()
    while d < depth and BASE64_PATTERN.match(current):
        try:
            decoded = base64.b64decode(current, validate=True).decode("utf-8")
        except Exception:
            break
        if not decoded or decoded == current:
            break
        current = decoded.strip()
        d += 1
        transformations.append("base64_decoded")
    return current


def _strip_markdown(text: str, transformations: list[str]) -> str:
    def _repl(m):
        return m.group(1) or m.group(2) or m.group(3) or ""

    out = MD_PATTERN.sub(_repl, text)
    if out != text:
        transformations.append("markdown_stripped")
    return out

def _strip_html(text: str, transformations: list[str]) -> str:
    out = HTML_TAG_PATTERN.sub("", text)
    if out != text:
        transformations.append("html_stripped")
    return out


# ---------- 主入口 ----------

def canonicalize(inp: CanonicalizeInput) -> CanonicalizeOutput:
    start = time.perf_counter()
    transformations: list[str] = []
    risk_signals: list[str] = []
    truncated = False

    text = inp.raw_text

    # 1. 长度预检
    if len(text.encode("utf-8")) > inp.max_bytes:
        text = text[: inp.max_bytes]
        truncated = True
        risk_signals.append("input_truncated")

    # 2. Unicode NFKC
    text = _nfkc(text, transformations)

    # 3. 零宽字符
    text = _strip_zero_width(text, transformations)

    # 4. 全角转半角
    text = _fullwidth_to_halfwidth(text, transformations)

    # 5. URL 解码
    text = _decode_url(text, inp.max_decode_depth, transformations)

    # 6. Base64 解码
    text = _decode_base64(text, inp.max_decode_depth, transformations)

    # 7. HTML 剥离
    text = _strip_html(text, transformations)

    # 8. Markdown 剥离
    text = _strip_markdown(text, transformations)

    # 9. 展开比例检查
    original_len = max(len(inp.raw_text), 1)
    if len(text) / original_len > inp.max_expansion_ratio:
        risk_signals.append("high_expansion_ratio")

    elapsed_ms = int((time.perf_counter() - start) * 1000)

    return CanonicalizeOutput(
        normalized_text=text.strip(),
        transformations=transformations,
        risk_signals=risk_signals,
        truncated=truncated,
        elapsed_ms=elapsed_ms,
    )