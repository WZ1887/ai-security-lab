"""客服 Agent 工具规划器。

输入：用户问题 + 可用工具列表
输出：工具调用意图（tool_name + arguments）
不执行工具，只规划。
"""

import json
import re
import time
from dataclasses import dataclass, field

import httpx

from app.main import settings


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict


@dataclass
class PlanResult:
    tool_name: str | None
    arguments: dict = field(default_factory=dict)
    reason: str = ""
    raw_response: str = ""
    elapsed_ms: int = 0


_SYSTEM_PROMPT = """You are a customer service agent. Given a user question and available tools, decide which tool to call and with what arguments.

Available tools:
{tools}

Rules:
1. Output ONLY a JSON object: {{"tool": "<tool_name>", "args": {{...}}}}
2. If no tool is needed, output {{"tool": null, "args": {{}}}}
3. Do not invent tool names. Use only the tools listed.
4. Do not output any explanation, only JSON.

Examples:
User: 帮我查一下订单 #10023
Output: {{"tool": "get_order", "args": {{"order_id": "10023"}}}}

User: 你好
Output: {{"tool": null, "args": {{}}}}
"""


def _format_tools(tools: list[ToolInfo]) -> str:
    lines = []
    for t in tools:
        lines.append(f"- {t.name}: {t.description} | args: {t.input_schema}")
    return "\n".join(lines)


def _extract_json(text: str) -> dict | None:
    # 直接解析
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass

    # 从 ```json ... ``` 提取
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    # 从文本中提取第一个 {...}
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass

    return None


def plan(user_input: str, tools: list[ToolInfo], timeout: float = 60.0) -> PlanResult:
    start = time.perf_counter()

    system = _SYSTEM_PROMPT.format(tools=_format_tools(tools))
    prompt = f"{system}\n\nUser: {user_input}\nOutput:"

    with httpx.Client(trust_env=False, timeout=timeout) as client:
        r = client.post(
            f"{settings.ollama_host}/api/generate",
            json={
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.0},
            },
        )
    r.raise_for_status()
    raw = r.json().get("response", "")

    parsed = _extract_json(raw)
    elapsed = int((time.perf_counter() - start) * 1000)

    if parsed is None:
        return PlanResult(
            tool_name=None,
            reason="PARSE_FAILED",
            raw_response=raw,
            elapsed_ms=elapsed,
        )

    tool_name = parsed.get("tool")
    args = parsed.get("args", {})

    if tool_name is None:
        return PlanResult(
            tool_name=None,
            reason="NO_TOOL_NEEDED",
            raw_response=raw,
            elapsed_ms=elapsed,
        )

    valid_names = {t.name for t in tools}
    if tool_name not in valid_names:
        return PlanResult(
            tool_name=None,
            reason=f"UNKNOWN_TOOL:{tool_name}",
            raw_response=raw,
            elapsed_ms=elapsed,
        )

    if not isinstance(args, dict):
        args = {}

    return PlanResult(
        tool_name=tool_name,
        arguments=args,
        reason="OK",
        raw_response=raw,
        elapsed_ms=elapsed,
    )
