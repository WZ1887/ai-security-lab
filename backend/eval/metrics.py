"""指标计算：混淆矩阵、按族拆分、延迟分位数。"""

from __future__ import annotations

from collections import Counter, defaultdict


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round(p / 100 * len(ordered))) - 1))
    return ordered[idx]


def summarize(results: list) -> dict:
    """results: list[SampleResult]（见 runner.py）。"""
    counted = [r for r in results if r.counted]
    attacks = [r for r in counted if r.sample.is_attack]
    benign = [r for r in counted if not r.sample.is_attack]

    tp = sum(1 for r in attacks if r.outcome == "tp")
    fn = sum(1 for r in attacks if r.outcome == "fn")
    tn = sum(1 for r in benign if r.outcome == "tn")
    fp = sum(1 for r in benign if r.outcome == "fp")

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    per_family: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    for r in counted:
        bucket = per_family[r.sample.family]
        bucket["total"] += 1
        bucket["pass" if r.outcome in ("tp", "tn") else "fail"] += 1

    failures = [
        {
            "id": r.sample.id,
            "family": r.sample.family,
            "expect": r.sample.expect,
            "outcome": r.outcome,
            "detail": r.detail,
        }
        for r in counted
        if r.outcome in ("fp", "fn") or r.outcome.endswith("fail")
    ]

    gate_hits = Counter(r.blocked_gate or "-" for r in counted if r.outcome == "tp")
    gate_latency: dict[str, list[float]] = defaultdict(list)
    for r in results:
        for gate, ms in (r.gate_ms or {}).items():
            if ms is not None:
                gate_latency[gate].append(float(ms))

    total_latency = [float(r.latency_ms) for r in results if r.latency_ms is not None]

    return {
        "total_samples": len(results),
        "counted_samples": len(counted),
        "skipped_samples": len(results) - len(counted),
        "attacks": len(attacks),
        "benign": len(benign),
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "per_family": {k: dict(v) for k, v in sorted(per_family.items())},
        "failures": failures,
        "gate_hits": dict(gate_hits),
        "gate_latency_p95": {
            gate: round(percentile(vals, 95), 2) for gate, vals in sorted(gate_latency.items())
        },
        "gate_latency_p50": {
            gate: round(percentile(vals, 50), 2) for gate, vals in sorted(gate_latency.items())
        },
        "total_latency_p50": round(percentile(total_latency, 50), 2),
        "total_latency_p95": round(percentile(total_latency, 95), 2),
    }


def render_markdown(summary: dict, meta: dict) -> str:
    lines: list[str] = []
    lines.append("# MCP-Guard 评测报告")
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    for key, value in meta.items():
        lines.append(f"| {key} | {value} |")
    lines.append(f"| 样本数 | {summary['total_samples']}（计入 {summary['counted_samples']}，"
                 f"跳过 {summary['skipped_samples']}） |")
    lines.append("")

    lines.append("## 总体指标")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Recall（攻击） | {summary['tp']}/{summary['attacks']} = {summary['recall']:.3f} |")
    lines.append(f"| Precision | {summary['precision']:.3f} |")
    lines.append(f"| FPR（良性被拦） | {summary['fp']}/{summary['benign']} = {summary['fpr']:.3f} |")
    lines.append(f"| 端点总延迟 p50 / p95 | {summary['total_latency_p50']} ms / {summary['total_latency_p95']} ms |")
    lines.append("")

    lines.append("## 逐 Gate 延迟（响应内计时）")
    lines.append("")
    lines.append("> 数字取自网关响应里各 Gate 的 `elapsed_ms`，整数毫秒；0 表示低于 1 ms。")
    lines.append("")
    lines.append("| Gate | p50 (ms) | p95 (ms) |")
    lines.append("|---|---|---|")
    gates = sorted(set(summary["gate_latency_p50"]) | set(summary["gate_latency_p95"]))
    for gate in gates:
        lines.append(
            f"| {gate} | {summary['gate_latency_p50'].get(gate, 0)} | {summary['gate_latency_p95'].get(gate, 0)} |"
        )
    lines.append("")

    lines.append("## 各族的拦截/放行是否符合作者预期")
    lines.append("")
    lines.append("| Family | Total | Pass | Fail |")
    lines.append("|---|---|---|---|")
    for family, stats in summary["per_family"].items():
        lines.append(f"| {family} | {stats['total']} | {stats['pass']} | {stats['fail']} |")
    lines.append("")

    lines.append("## 拦截发生在哪一层")
    lines.append("")
    lines.append("| Gate | 命中数 |")
    lines.append("|---|---|")
    for gate, count in sorted(summary["gate_hits"].items()):
        lines.append(f"| {gate} | {count} |")
    lines.append("")

    if summary["failures"]:
        lines.append("## 未通过的样本")
        lines.append("")
        lines.append("| id | family | expect | outcome | detail |")
        lines.append("|---|---|---|---|---|")
        for f in summary["failures"]:
            lines.append(
                f"| {f['id']} | {f['family']} | {f['expect']} | {f['outcome']} | {f['detail']} |"
            )
        lines.append("")
    return "\n".join(lines)
