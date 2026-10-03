"""G2 Semantic Risk Gate。

只产出风险信号，不做最终判定。
"""

import time
from dataclasses import dataclass, field
from typing import Literal

from app.mcp_guard.semantic.anchors import ANCHORS, BENIGN_ANCHORS
from app.mcp_guard.semantic.embedder import cosine, embed


RiskAction = Literal["ALLOW", "REVIEW", "REQUIRE_APPROVAL"]


@dataclass
class SemanticInput:
    normalized_text: str
    source: str = "user"
    context_window: list[str] = field(default_factory=list)


@dataclass
class SemanticOutput:
    risk_score: float
    signals: list[str]
    action: RiskAction
    anchor_scores: dict[str, float]
    benign_score: float
    margin: float
    elapsed_ms: int


# 阈值
REVIEW_THRESHOLD = 0.60
APPROVAL_THRESHOLD = 0.85
MARGIN_MIN = 0.05           # 恶意分至少要比良性分高这么多，才考虑判定


_anchor_vecs: dict[str, list[tuple[str, list[float]]]] = {}
_benign_vecs: list[tuple[str, list[float]]] = []


def _load_anchors() -> None:
    if _anchor_vecs and _benign_vecs:
        return
    for category, examples in ANCHORS.items():
        _anchor_vecs[category] = [(ex, embed(ex)) for ex in examples]
    _benign_vecs.clear()
    for ex in BENIGN_ANCHORS:
        _benign_vecs.append((ex, embed(ex)))


def _max_sim_per_category(text_vec: list[float]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for category, items in _anchor_vecs.items():
        best = 0.0
        for _, vec in items:
            s = cosine(text_vec, vec)
            if s > best:
                best = s
        scores[category] = best
    return scores


def _max_benign_sim(text_vec: list[float]) -> float:
    best = 0.0
    for _, vec in _benign_vecs:
        s = cosine(text_vec, vec)
        if s > best:
            best = s
    return best


def _decide(malicious_top: float, margin: float) -> RiskAction:
    # 低于审查阈值，直接放行
    if malicious_top < REVIEW_THRESHOLD:
        return "ALLOW"
    # margin 太小，说明更像是良性场景
    if margin < MARGIN_MIN:
        return "ALLOW"
    # 恶意分够高，进入审批
    if malicious_top >= APPROVAL_THRESHOLD:
        return "REQUIRE_APPROVAL"
    return "REVIEW"


def analyze(inp: SemanticInput) -> SemanticOutput:
    start = time.perf_counter()

    _load_anchors()

    # 分片拼接
    merged = "\n".join(inp.context_window + [inp.normalized_text])

    text_vec = embed(merged)
    anchor_scores = _max_sim_per_category(text_vec)
    benign_score = _max_benign_sim(text_vec)

    top_category = max(anchor_scores, key=anchor_scores.get)  # type: ignore
    top_score = anchor_scores[top_category]
    margin = top_score - benign_score

    signals: list[str] = []
    if top_score >= REVIEW_THRESHOLD and margin >= MARGIN_MIN:
        signals.append(top_category)
    if sum(1 for s in anchor_scores.values() if s >= REVIEW_THRESHOLD) >= 2 and margin >= MARGIN_MIN:
        signals.append("multi_category_hit")
    if margin < 0:
        signals.append("benign_dominant")

    action = _decide(top_score, margin)

    elapsed_ms = int((time.perf_counter() - start) * 1000)

    return SemanticOutput(
        risk_score=round(top_score, 4),
        signals=signals,
        action=action,
        anchor_scores={k: round(v, 4) for k, v in anchor_scores.items()},
        benign_score=round(benign_score, 4),
        margin=round(margin, 4),
        elapsed_ms=elapsed_ms,
    )