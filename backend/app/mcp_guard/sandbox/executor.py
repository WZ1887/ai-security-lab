"""沙箱执行器。

MVP 版本：
  - 路径白名单校验
  - 参数类型/长度校验
  - 真实工具调用由 MCP Server 提供，这里只做安全校验 + 转发
  - 不做真实子进程隔离（后续可换 Docker / nsjail）

核心目的：拒绝越权资源访问（P8），不直接执行敏感操作。
"""

import os
import time
from dataclasses import dataclass, field
from typing import Callable


ALLOWED_ROOT = os.path.abspath("./sandbox_root")


@dataclass
class SandboxInput:
    tool_name: str
    arguments: dict
    executor: Callable[[str, dict], dict] | None = None


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


def _check_path(path: str) -> bool:
    """检查路径是否在允许的根目录下。"""
    try:
        abs_path = os.path.abspath(path)
    except Exception:
        return False
    return abs_path.startswith(ALLOWED_ROOT)


def _check_arguments(tool_name: str, args: dict) -> str:
    if not isinstance(args, dict):
        return "ARGS_NOT_DICT"

    # 文件类工具：路径白名单
    if tool_name in ("read_file", "write_file"):
        path = args.get("path") or args.get("resource") or ""
        if not _check_path(path):
            return "SANDBOX_PATH_VIOLATION"

    # 字符串长度上限，防 Token 炸弹
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 8192:
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

    try:
        result = inp.executor(inp.tool_name, inp.arguments)
    except Exception as e:
        return _fail(f"EXECUTION_ERROR:{type(e).__name__}", start)

    return SandboxOutput(
        success=True,
        result=result,
        reason="OK",
        elapsed_ms=int((time.perf_counter() - start) * 1000),
    )