"""Deterministic scoring with correlation damping and evidence-diversity support."""

from __future__ import annotations

from typing import Iterable

from app.schemas.analysis import ThreatSignal


ANALYZER_CATEGORIES = {'url', 'content', 'header', 'attachment', 'metadata'}
DIMINISHING_FACTORS = (1.0, 0.75, 0.55, 0.40, 0.30)
CATEGORY_CAPS = {'url': 65, 'content': 65, 'header': 60, 'attachment': 55, 'metadata': 10}


def calculate_raw_risk_score(signals: Iterable[ThreatSignal]) -> int:
    unique = {signal.code: signal for signal in signals}
    return int(min(100, sum(signal.score for signal in unique.values())))


def calculate_risk_score(signals: Iterable[ThreatSignal]) -> int:
    unique = {s.code: s for s in signals}
    # Preserve simple additive behavior for third-party/legacy categories. Built-in analyzers
    # use diminishing returns so correlated rules cannot dominate the verdict.
    if not set(s.category for s in unique.values()).issubset(ANALYZER_CATEGORIES):
        return int(min(100, sum(s.score for s in unique.values())))

    category_scores: list[int] = []
    for category in ANALYZER_CATEGORIES:
        contributions = sorted(
            (signal.score for signal in unique.values() if signal.category == category and signal.score > 0),
            reverse=True,
        )
        weighted = sum(
            score * DIMINISHING_FACTORS[min(index, len(DIMINISHING_FACTORS) - 1)]
            for index, score in enumerate(contributions)
        )
        if weighted:
            category_scores.append(min(CATEGORY_CAPS[category], round(weighted)))

    # Independent evidence types reinforce one another. No diversity bonus is possible for
    # a single weak finding, while several medium findings combine without linear inflation.
    diversity_bonus = max(0, len(category_scores) - 1) * 4
    return int(min(100, sum(category_scores) + diversity_bonus))


def classify_risk_score(score: int):
    if score <= 29:
        return 'safe'
    if 30 <= score <= 69:
        return 'suspicious'
    return 'phishing'


def calculate_confidence(score: int, signals: Iterable[ThreatSignal]) -> float:
    unique = {s.code: s for s in signals}
    positive = [signal for signal in unique.values() if signal.score > 0]
    categories = {signal.category for signal in positive}
    if not positive:
        return 0.78

    diversity = min(1.0, len(categories) / 4.0)
    evidence_count = min(1.0, len(positive) / 6.0)
    if score < 30:
        threshold_distance = (30 - score) / 30.0
    elif score < 70:
        threshold_distance = min(score - 30, 70 - score) / 20.0
    else:
        threshold_distance = (score - 70) / 30.0
    confidence = 0.48 + 0.20 * diversity + 0.17 * evidence_count + 0.15 * min(1.0, threshold_distance)
    return round(min(1.0, confidence), 3)
