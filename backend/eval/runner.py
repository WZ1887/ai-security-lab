"""评测运行器：把样本喂给真实的 Gateway / 沙箱，收集结果。

语义模式（--semantic）：
  offline （默认）把嵌入层替换成"不可用"，模拟没有模型的环境。
                    这是受支持的部署状态：G2 标记 degraded，中高风险工具转人工审批。
                    因此期望结果依赖模型的样本要标 requires_model=true，离线时会跳过。
  auto             模型可用就用真实模型；不可用则退化为 offline。
  required         模型必须可用，否则报错（做阈值标定时用）。
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings
from app.mcp_guard.canonicalize.g1 import CanonicalizeInput, canonicalize
from app.mcp_guard.gateway import GatewayRequest, handle_tool_call
from app.mcp_guard.registry.sync import build_tool_index, sync_from_servers
from app.mcp_guard.sandbox.executor import SandboxInput
from app.mcp_guard.sandbox.executor import execute as sandbox_execute
from app.memory import service as memory_service
from app.models import approval, audit_event, memory, policy_rule, tool_registry, user  # noqa: F401
from app.models.base import Base
from app.models.tool_registry import ToolRegistry
from eval.dataset import Sample


@dataclass
class SampleResult:
    sample: Sample
    outcome: str            # tp / tn / fp / fn / normalized_fail / skipped
    detail: str = ""
    latency_ms: int = 0
    gate_ms: dict = field(default_factory=dict)
    blocked_gate: str | None = None
    reason: str | None = None
    counted: bool = True


def ollama_available(timeout: float = 1.0) -> bool:
    try:
        r = httpx.get(f"{settings.ollama_host}/api/tags", timeout=timeout, trust_env=False)
        return r.status_code < 400
    except Exception:
        return False


class EvalHarness:
    """一次评测用一套独立的 SQLite 库 + 工具注册表。"""

    def __init__(self, semantic_mode: str = "offline") -> None:
        self.semantic_mode = semantic_mode
        self.tmpdir = Path(tempfile.mkdtemp(prefix="mcpguard_eval_"))
        self.engine = create_engine(
            f"sqlite:///{self.tmpdir / 'eval.db'}",
            connect_args={"check_same_thread": False},
            poolclass=NullPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()
        sync_from_servers(self.db)
        memory_service.set_session_factory(self.SessionLocal)
        self.index = build_tool_index()
        self._restore: list[tuple] = []
        self.effective_semantic = semantic_mode

    # ---------- 生命周期 ----------

    def __enter__(self) -> "EvalHarness":
        if self.semantic_mode in ("auto", "required"):
            if not ollama_available():
                if self.semantic_mode == "required":
                    raise RuntimeError("--semantic required 需要 Ollama，但探测失败")
                self.effective_semantic = "offline"

        if self.semantic_mode == "offline" or self.effective_semantic == "offline":
            self._force_semantic_offline()
        return self

    def __exit__(self, *exc) -> None:
        for obj, attr, original in reversed(self._restore):
            setattr(obj, attr, original)
        self._restore.clear()
        memory_service.set_session_factory(None)
        self.db.close()

    def _force_semantic_offline(self) -> None:
        """让 G2 立刻"嵌入不可用"，避免评测里出现网络等待。"""
        import app.mcp_guard.semantic.embedder as embedder
        import app.mcp_guard.semantic.g2 as g2

        def _fail(*_args, **_kwargs):
            raise RuntimeError("semantic offline (eval mode)")

        self._restore.append((embedder, "embed", embedder.embed))
        self._restore.append((g2, "embed", g2.embed))
        embedder.embed = _fail
        g2.embed = _fail

    # ---------- 单条样本 ----------

    def run_sample(self, sample: Sample) -> SampleResult:
        if sample.expect == "normalized":
            return self._run_normalization(sample)
        if sample.target == "sandbox":
            return self._run_sandbox(sample)
        return self._run_gateway(sample)

    def _run_normalization(self, sample: Sample) -> SampleResult:
        start = time.perf_counter()
        out = canonicalize(CanonicalizeInput(raw_text=sample.user_input, source="user"))
        latency = int((time.perf_counter() - start) * 1000)
        missing = [t for t in sample.expect_transformations if t not in out.transformations]
        if missing:
            return SampleResult(
                sample,
                "normalized_fail",
                detail=f"缺少变换 {missing}，实际 {out.transformations}",
                latency_ms=latency,
                gate_ms={"g1": out.elapsed_ms},
                blocked_gate=None,
                reason=",".join(out.transformations) or "NO_TRANSFORMATION",
            )
        return SampleResult(
            sample,
            "tn",
            detail="归一化符合预期",
            latency_ms=latency,
            gate_ms={"g1": out.elapsed_ms},
            reason=",".join(out.transformations),
        )

    def _run_sandbox(self, sample: Sample) -> SampleResult:
        start = time.perf_counter()
        called = {"n": 0}

        def _executor(_name, _args, _ctx):
            called["n"] += 1
            return {"ok": True}

        out = sandbox_execute(
            SandboxInput(
                tool_name=sample.tool or "read_file",
                arguments=sample.arguments,
                executor=_executor,
            )
        )
        latency = int((time.perf_counter() - start) * 1000)
        blocked = not out.success
        if sample.expect == "blocked":
            ok = blocked and (sample.reason_contains or "") in (out.reason or "")
            return SampleResult(
                sample,
                "tp" if ok else "fn",
                detail=f"sandbox reason={out.reason} executor_called={called['n']}",
                latency_ms=latency,
                gate_ms={},
                blocked_gate="G5" if blocked else None,
                reason=out.reason,
            )
        ok = (not blocked) and called["n"] == 1
        return SampleResult(
            sample,
            "tn" if ok else "fp",
            detail=f"sandbox success={out.success} executor_called={called['n']}",
            latency_ms=latency,
            gate_ms={},
            reason=out.reason,
        )

    def _run_gateway(self, sample: Sample) -> SampleResult:
        # 未注册的工具 / 空工具名（不需要工具调用）都照常走网关：
        # 前者由 G3 拒绝，后者由网关返回 NO_TOOL_CALL。
        meta = self.index.get(sample.tool, {}) if sample.tool else {}

        hashes = {
            "input_schema_hash": meta.get("input_schema_hash", ""),
            "description_hash": meta.get("description_hash", ""),
            "capability_hash": meta.get("capability_hash", ""),
            "output_schema_hash": meta.get("output_schema_hash", ""),
        }
        hashes.update(sample.tool_overrides)
        fingerprint = sample.tool_overrides.get(
            "server_fingerprint", meta.get("server_fingerprint", "")
        )

        executor = meta.get("executor")
        if sample.tool_result is not None:
            executor = lambda _n, _a, _c, _r=sample.tool_result: _r

        restore_row = None
        saved_values: dict = {}
        if sample.registry_patch:
            restore_row = (
                self.db.query(ToolRegistry)
                .filter(ToolRegistry.server_id == meta.get("server_id", ""))
                .filter(ToolRegistry.tool_name == sample.tool)
                .first()
            )
            if restore_row is not None:
                for key in sample.registry_patch:
                    saved_values[key] = getattr(restore_row, key, None)
                    setattr(restore_row, key, sample.registry_patch[key])
                self.db.commit()

        start = time.perf_counter()
        try:
            resp = handle_tool_call(
                self.db,
                GatewayRequest(
                    session_id=f"eval_{sample.id}",
                    user_id=sample.user_id,
                    tenant_id=sample.tenant_id,
                    roles=sample.roles,
                    agent_id=f"eval_{sample.id}",
                    user_input=sample.user_input,
                    server_id=meta.get("server_id", ""),
                    server_fingerprint=fingerprint,
                    tool_name=sample.tool,
                    tool_version=meta.get("tool_version", ""),
                    tool_input_schema=meta.get("input_schema", {}),
                    tool_arguments=sample.arguments,
                    tool_hashes=hashes,
                    data_labels_in=sample.data_labels_in,
                    executor=executor,
                ),
            )
        finally:
            if restore_row is not None and saved_values:
                for key, value in saved_values.items():
                    setattr(restore_row, key, value)
                self.db.commit()
        latency = int((time.perf_counter() - start) * 1000)
        gate_ms = {}
        for gate_name in ("g1", "g2", "g3", "g4", "g5"):
            value = (getattr(resp, gate_name) or {}).get("elapsed_ms")
            if value is not None:
                gate_ms[gate_name] = value

        blocked = not resp.allowed
        reason = resp.final_reason

        if sample.expect == "tool_denied":
            # 策略放行、但工具层按归属/资源规则拒绝：结果里必须是错误载荷
            result = resp.result if isinstance(resp.result, dict) else {}
            denied = bool(result.get("error")) or "TOOL_ERROR" in (resp.result_labels or [])
            return SampleResult(
                sample,
                "tp" if denied else "fn",
                detail=f"decision={resp.decision} result={result} labels={resp.result_labels}",
                latency_ms=latency,
                gate_ms=gate_ms,
                blocked_gate=resp.blocked_gate,
                reason=reason,
            )

        if sample.expect == "blocked":
            ok = blocked
            if ok and sample.gate and resp.blocked_gate != sample.gate:
                ok = False
            if ok and sample.reason_contains and sample.reason_contains not in (reason or ""):
                ok = False
            return SampleResult(
                sample,
                "tp" if ok else "fn",
                detail=f"decision={resp.decision} gate={resp.blocked_gate} reason={reason}",
                latency_ms=latency,
                gate_ms=gate_ms,
                blocked_gate=resp.blocked_gate,
                reason=reason,
            )

        return SampleResult(
            sample,
            "tn" if not blocked else "fp",
            detail=f"decision={resp.decision} gate={resp.blocked_gate} reason={reason}",
            latency_ms=latency,
            gate_ms=gate_ms,
            blocked_gate=resp.blocked_gate,
            reason=reason,
        )

    # ---------- 批量 ----------

    def run_all(self, samples: list[Sample]) -> list[SampleResult]:
        results: list[SampleResult] = []
        for sample in samples:
            if sample.requires_model and self.effective_semantic == "offline":
                results.append(
                    SampleResult(
                        sample,
                        "skipped",
                        detail="requires_model：离线模式下 G2 不可用，期望结果不成立",
                        counted=False,
                    )
                )
                continue
            results.append(self.run_sample(sample))
        return results
