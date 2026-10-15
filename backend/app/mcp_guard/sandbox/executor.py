"""沙箱执行器。

MVP 版本：
  - 资源路径白名单校验（真实路径归一 + 目录前缀判定 + symlink 逃逸检查）
  - 参数类型/长度校验
  - 真实工具调用由 MCP Server 提供，这里只做安全校验 + 转发
  - 不做真实子进程隔离（后续可换 Docker / nsjail）

核心目的：拒绝越权资源访问（P8），不直接执行敏感操作。
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.config import settings
from app.mcp_servers.context import CallContext


def allowed_root() -> Path:
    """沙箱根目录。

    优先取配置；默认锚定到仓库根下的 sandbox_root。
    旧实现是 os.path.abspath("./sandbox_root")，结果取决于进程 CWD
    （README 让你 cd backend 启动，根目录就歪了）。
    """
    configured = (settings.sandbox_root or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(__file__).resolve().parents[4] / "sandbox_root").resolve()


@dataclass
class SandboxInput:
    tool_name: str
    arguments: dict
    executor: Callable[[str, dict, CallContext], dict] | None = None
    context: CallContext | None = None


@dataclass
class SandboxOutput:
    success: bool
    result: dict = field(default_factory=dict)
    reason: str = "OK"
    elapsed_ms: int = 0


def _fail(reason: str, start: float) -> SandboxOutput:
    return SandboxOutput(
        success=False,
        reason=reason,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )


def _is_within(path: Path, root: Path) -> bool:
    """path 是否等于 root 或位于 root 之下。

    旧实现用字符串 startswith 判前缀：/app/sandbox_root_evil 会被误判为合法，
    Windows 大小写不一致也会漏判。这里按路径分量比较。
    """
    try:
        resolved = path.resolve()
    except Exception:
        return False
    root_key = os.path.normcase(str(root))
    path_key = os.path.normcase(str(resolved))
    return path_key == root_key or path_key.startswith(root_key + os.sep)


def _check_path(path: str) -> bool:
    """检查路径是否在允许的根目录下。"""
    if not path or not isinstance(path, str):
        return False

    root = allowed_root()
    # 相对路径一律解释成“沙箱根目录下的相对路径”，
    # 于是 "../../etc/passwd" 会立刻跑到根目录之外被拒。
    candidate = Path(path) if os.path.isabs(path) else root / path
    if not _is_within(candidate, root):
        return False

    # 已存在的路径再解析一次，防 symlink 指向沙箱外
    try:
        real = candidate.resolve(strict=True)
    except FileNotFoundError:
        # 目标还不存在：由工具自身处理，路径本身的归属已经校验过
        return True
    except Exception:
        return False
    return _is_within(real, root)


def _check_arguments(tool_name: str, args: dict) -> str:
    if not isinstance(args, dict):
        return "ARGS_NOT_DICT"

    # 文件类工具：路径白名单
    if tool_name in ("read_file", "write_file"):
        path = args.get("path") or args.get("resource") or ""
        if not _check_path(path):
            return "SANDBOX_PATH_VIOLATION"

    # 字符串长度上限，防 Token 炸弹
    max_chars = settings.sandbox_max_arg_chars
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_chars:
            return f"ARG_TOO_LONG:{k}"

    return "OK"


def execute(inp: SandboxInput) -> SandboxOutput:
    start = time.perf_counter()

    # 1. 参数校验
    reason = _check_arguments(inp.tool_name, inp.arguments)
    if reason != "OK":
        return _fail(reason, start)

    # 2. 转发执行
    if inp.executor is None:
        return SandboxOutput(
            success=True,
            result={"echo": inp.arguments},
            reason="OK_NO_EXECUTOR",
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )

    # 身份随调用一起下发，工具内部据此做资源归属校验
    context = inp.context or CallContext()
    try:
        result = inp.executor(inp.tool_name, inp.arguments, context)
    except Exception as e:
        return _fail(f"EXECUTION_ERROR:{type(e).__name__}", start)

    return SandboxOutput(
        success=True,
        result=result,
        reason="OK",
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )
