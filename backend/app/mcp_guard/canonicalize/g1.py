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
    expansion_ratio: float = 1.0
    elapsed_ms: int = 0


# ---------- 常量 ----------

# 显式清单之外的不可见字符按 Unicode 类别 / 码位区间处理，见 _is_invisible
ZERO_WIDTH = [
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
    "\u00ad", "\u180e", "\ufe0e", "\ufe0f",
]

_HEX_PAIR = re.compile(r"[0-9A-Fa-f]{2}")
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# 只剥真的像 HTML 标签的东西：必须以字母或 / 开头。
# 旧写法 <[^>]+> 会把 "<|system|>" 这类注入标记当标签删掉，等于替攻击者净化了输入。
HTML_TAG_PATTERN = re.compile(r"</?[a-zA-Z][^>]*>")
MD_PATTERN = re.compile(r"\*\*(.+?)\*\*|`(.+?)`|\[(.+?)\]\(.+?\)")


def _is_invisible(ch: str) -> bool:
    """零宽 / 格式化字符（Cf）/ 变体选择符 / tag 字符。"""
    if ch in ZERO_WIDTH:
        return True
    if unicodedata.category(ch) == "Cf":
        return True
    code = ord(ch)
    return (
        0xFE00 <= code <= 0xFE0F        # 变体选择符 VS1–VS16
        or 0xE0100 <= code <= 0xE01EF   # 变体选择符 VS17–VS256
        or 0xE0000 <= code <= 0xE007F   # tag block
    )


# ---------- 单步变换 ----------

def _strip_invisible(text: str, transformations: list[str]) -> str:
    """移除不可见字符。

    覆盖：显式清单 + Unicode 类别 Cf + 变体选择符 + tag block。
    这是有意的取舍——ZWJ(U+200D) 在 emoji / 部分文字里有语义，
    但安全网关优先保证“人眼看到的文本 == 被检测的文本”。
    变换名沿用 zero_width_removed，保持与 docs 里的证据字段一致。
    """
    out = [ch for ch in text if not _is_invisible(ch)]
    if len(out) != len(text):
        transformations.append("zero_width_removed")
    return "".join(out)


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


def _percent_decode_once(text: str) -> tuple[str, bool, bool]:
    """解码一层 %XX。返回 (结果, 是否有解码, 是否出现无效 UTF-8)。"""
    out: list[str] = []
    buf = bytearray()
    changed = False
    lossy = False

    def flush() -> None:
        nonlocal lossy
        if not buf:
            return
        decoded = buf.decode("utf-8", errors="replace")
        if "\ufffd" in decoded:
            lossy = True
        out.append(decoded)
        buf.clear()

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "%" and i + 3 <= n and _HEX_PAIR.fullmatch(text[i + 1 : i + 3]):
            buf.append(int(text[i + 1 : i + 3], 16))
            changed = True
            i += 3
            continue
        if ord(ch) < 0x80:
            buf.append(ord(ch))
        else:
            # 非 ASCII 字符本身不是字节序列，先冲掉缓冲区再原样保留
            flush()
            out.append(ch)
        i += 1
    flush()
    return "".join(out), changed, lossy


def _decode_url(
    text: str,
    depth: int,
    transformations: list[str],
    risk_signals: list[str],
) -> str:
    """解码 %XX 序列，字节串按 UTF-8 还原。

    旧实现逐字节 decode("latin-1")，中文百分号编码会变成乱码
    （"%E5%BF%BD" → "å¿½"），等于给中文混淆留了后门。
    """
    changed_any = False
    for _ in range(max(0, depth)):
        decoded, changed, lossy = _percent_decode_once(text)
        if not changed:
            break
        text = decoded
        changed_any = True
        if lossy and "url_decode_invalid_utf8" not in risk_signals:
            risk_signals.append("url_decode_invalid_utf8")
    if changed_any:
        transformations.append("url_decoded")
    return text


def _try_base64(candidate: str) -> str | None:
    """只接受“解码后像正常文本”的候选，避免误伤普通字符串。"""
    if len(candidate) < 16 or len(candidate) % 4 == 1:
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except Exception:
        return None
    if len(decoded) < 4 or decoded == candidate:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    if printable / len(decoded) < 0.9:
        return None
    return decoded


def _decode_base64_once(text: str) -> tuple[str, bool]:
    changed = False

    def _repl(m: re.Match) -> str:
        nonlocal changed
        plain = _try_base64(m.group(0))
        if plain is None:
            return m.group(0)
        changed = True
        return plain

    return _B64_CANDIDATE.sub(_repl, text), changed


def _decode_base64(text: str, depth: int, transformations: list[str]) -> str:
    """解码文本中内嵌的 Base64 片段。

    旧实现只在“整串恰好匹配”时才解，句子里夹带 payload 可以完全绕过。
    """
    depth_left = max(0, depth)
    changed_any = False
    while depth_left > 0:
        decoded, changed = _decode_base64_once(text)
        if not changed:
            break
        text = decoded
        depth_left -= 1
        changed_any = True
    if changed_any:
        transformations.append("base64_decoded")
    return text


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

def _truncate_bytes(text: str, max_bytes: int) -> str:
    """按字节安全截断：不切开多字节字符（旧实现按字符切片，可能超上限）。"""
    return text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")


def canonicalize(inp: CanonicalizeInput) -> CanonicalizeOutput:
    start = time.perf_counter()
    transformations: list[str] = []
    risk_signals: list[str] = []
    truncated = False

    text = inp.raw_text
    original_bytes = len(text.encode("utf-8"))

    # 1. 长度预检
    if original_bytes > inp.max_bytes:
        text = _truncate_bytes(text, inp.max_bytes)
        truncated = True
        risk_signals.append("input_truncated")

    # 2. Unicode NFKC
    text = _nfkc(text, transformations)

    # 3. 不可见字符（零宽 / Cf / 变体选择符 / tag）
    text = _strip_invisible(text, transformations)

    # 4. 全角转半角
    text = _fullwidth_to_halfwidth(text, transformations)

    # 5. URL 解码
    text = _decode_url(text, inp.max_decode_depth, transformations, risk_signals)

    # 6. Base64 解码
    text = _decode_base64(text, inp.max_decode_depth, transformations)

    # 7. HTML 剥离
    text = _strip_html(text, transformations)

    # 8. Markdown 剥离
    text = _strip_markdown(text, transformations)

    # 9. 展开比例检查（按字节：NFKC 兼容分解是真实的膨胀来源）
    expansion_ratio = len(text.encode("utf-8")) / max(original_bytes, 1)
    if expansion_ratio > inp.max_expansion_ratio:
        risk_signals.append("high_expansion_ratio")

    elapsed_ms = int((time.perf_counter() - start) * 1000)

    return CanonicalizeOutput(
        normalized_text=text.strip(),
        transformations=transformations,
        risk_signals=risk_signals,
        truncated=truncated,
        expansion_ratio=round(expansion_ratio, 4),
        elapsed_ms=elapsed_ms,
    )
