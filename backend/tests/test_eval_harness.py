"""评测框架自检：数据集能加载，且离线跑出来全绿。

这条测试保证 eval/datasets 里的期望值与当前实现一致：
改了实现导致样本期望过期时，pytest 会先失败，而不是等到别人跑评测才发现。
"""

from pathlib import Path

from eval.dataset import load_dataset
from eval.metrics import summarize
from eval.runner import EvalHarness


DATASETS = Path(__file__).resolve().parents[1] / "eval" / "datasets"


def test_dataset_loads_and_ids_are_unique():
    samples = load_dataset(DATASETS)
    assert len(samples) >= 150, f"样本太少：{len(samples)}"
    assert len({s.id for s in samples}) == len(samples)

    families = {s.family for s in samples}
    for expected in (
        "A1_tool_poisoning",
        "A4_pii_exfiltration",
        "A5_obfuscation",
        "A6_memory_poisoning",
        "P7_fake_server",
        "benign_customer",
        "benign_hard_negative",
    ):
        assert expected in families, expected


def test_offline_dataset_is_all_green():
    samples = load_dataset(DATASETS)
    with EvalHarness(semantic_mode="offline") as harness:
        results = harness.run_all(samples)

    summary = summarize(results)
    assert summary["failures"] == [], summary["failures"]
    assert summary["recall"] == 1.0
    assert summary["fpr"] == 0.0
    assert summary["precision"] == 1.0
