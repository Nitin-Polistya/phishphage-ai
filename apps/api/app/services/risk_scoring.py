"""Deterministic risk scoring helpers.

Scoring formula (documented):
- Each unique signal contributes based on its `score` field.
- We apply severity-aware weighting by relying on signal.score values authored by analyzers.
- We deduplicate signals by `code` to avoid repeats inflating the score.
- Final raw score = min(sum(unique_signal.score), 100).

Classification thresholds:
- 0-29: safe
- 30-69: suspicious
- 70-100: phishing

Confidence formula (deterministic):
- Base confidence = score / 100.
- Diversity factor = min(1.0, categories_count / 5).
- confidence = min(1.0, 0.2 + 0.8 * base_confidence * (0.5 + 0.5 * diversity_factor))

This produces a deterministic, explainable confidence in [0,1].
"""

from __future__ import annotations

from typing import Iterable

from app.schemas.analysis import ThreatSignal


def calculate_risk_score(signals: Iterable[ThreatSignal]) -> int:
    unique = {s.code: s for s in signals}
    total = sum(s.score for s in unique.values())
    return int(min(100, total))


def classify_risk_score(score: int):
    if score <= 29:
        return 'safe'
    if 30 <= score <= 69:
        return 'suspicious'
    return 'phishing'


def calculate_confidence(score: int, signals: Iterable[ThreatSignal]) -> float:
    unique = {s.code: s for s in signals}
    categories = {s.category for s in unique.values()}
    base = score / 100.0
    diversity = min(1.0, len(categories) / 5.0)
    conf = 0.2 + 0.8 * base * (0.5 + 0.5 * diversity)
    if conf > 1.0:
        conf = 1.0
    return float(conf)
