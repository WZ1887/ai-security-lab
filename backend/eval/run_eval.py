"""评测 CLI。

    cd backend
    python -m eval.run_eval                          # 离线（默认，不需要 Ollama）
    python -m eval.run_eval --semantic required       # 带模型跑（含 G2 分数分布）
    python -m eval.run_eval --markdown eval/report.md --json eval/report.json

退出码：未达标（失败样本数 / recall / FPR 超阈值）返回 1，可直接当 CI 门禁。
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path


def _repo_backend_on_path() -> None:
    backend = Path(__file__).resolve().parents[1]
    if str(backend) not in sys.path:
        sys.path.insert(0, str(backend))


def main(argv: list[str] | None = None) -> int:
    _repo_backend_on_path()

    from eval.dataset import load_dataset
    from eval.metrics import render_markdown, summarize
    from eval.runner import EvalHarness

    parser = argparse.ArgumentParser(description="MCP-Guard 评测")
    parser.add_argument("--datasets", default=str(Path(__file__).resolve().parent / "datasets"),
                        help="JSONL 文件或目录（默认 eval/datasets）")
    parser.add_argument("--semantic", choices=("offline", "auto", "required"), default="offline")
    parser.add_argument("--json", dest="json_out", default="")
    parser.add_argument("--markdown", dest="markdown_out", default="")
    parser.add_argument("--max-failures", type=int, default=0)
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--max-fpr", type=float, default=0.0)
    parser.add_argument("--min-precision", type=float, default=1.0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    samples = load_dataset(Path(args.datasets))
    with EvalHarness(semantic_mode=args.semantic) as harness:
        results = harness.run_all(samples)
        effective = harness.effective_semantic

    summary = summarize(results)
    try:
        dataset_display = str(Path(args.datasets).resolve().relative_to(Path.cwd()))
    except Exception:
        dataset_display = str(args.datasets)
    meta = {
        "生成时间": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "语义模式": f"{args.semantic}（实际 {effective}）",
        "样本目录": dataset_display,
        "Python": platform.python_version(),
        "平台": platform.platform(),
    }

    print("=" * 64)
    print("MCP-Guard 评测")
    print("=" * 64)
    for key, value in meta.items():
        print(f"{key:<10}: {value}")
    print("-" * 64)
    print(f"样本           : {summary['total_samples']}"
          f"（计入 {summary['counted_samples']}，跳过 {summary['skipped_samples']}）")
    print(f"攻击拦截 Recall: {summary['tp']}/{summary['attacks']} = {summary['recall']:.3f}")
    print(f"Precision      : {summary['precision']:.3f}")
    print(f"良性误报 FPR   : {summary['fp']}/{summary['benign']} = {summary['fpr']:.3f}")
    print(f"端到端延迟     : p50 {summary['total_latency_p50']} ms / p95 {summary['total_latency_p95']} ms")
    print(f"逐 Gate p95    : {summary['gate_latency_p95']}")
    print(f"拦截分布       : {summary['gate_hits']}")

    failed = summary["failures"]
    if failed:
        print("-" * 64)
        print(f"未通过 {len(failed)} 条：")
        for item in failed:
            print(f"  [{item['id']}] {item['family']} 期望 {item['expect']} -> {item['outcome']}"
                  f" | {item['detail']}")
    if args.verbose:
        print("-" * 64)
        for r in results:
            print(f"  {r.outcome:<15} {r.sample.id:<28} {r.detail}")

    if args.markdown_out:
        Path(args.markdown_out).write_text(render_markdown(summary, meta), encoding="utf-8")
        print(f"Markdown 报告  : {args.markdown_out}")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps({"meta": meta, "summary": summary}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"JSON 结果      : {args.json_out}")

    problems = []
    if len(failed) > args.max_failures:
        problems.append(f"失败样本 {len(failed)} > {args.max_failures}")
    if summary["recall"] < args.min_recall:
        problems.append(f"recall {summary['recall']:.3f} < {args.min_recall}")
    if summary["fpr"] > args.max_fpr:
        problems.append(f"FPR {summary['fpr']:.3f} > {args.max_fpr}")
    if summary["precision"] < args.min_precision:
        problems.append(f"precision {summary['precision']:.3f} < {args.min_precision}")

    if problems:
        print("-" * 64)
        print("未达标：" + "；".join(problems))
        return 1
    print("-" * 64)
    print("达标 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
