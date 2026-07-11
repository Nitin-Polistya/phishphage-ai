"""Typed configuration for the PhishShield ML baseline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class MLConfig:
    model_version: str = "ml-baseline-v1.0.0"
    preprocessing_version: str = "preprocess-v1.0.0"
    random_state: int = 42
    train_ratio: float = 0.70
    validation_ratio: float = 0.15
    test_ratio: float = 0.15
    min_df: int = 1
    max_df: float = 0.95
    max_features: int | None = 20000
    max_iter: int = 1000
    model_output: Path = field(default_factory=lambda: Path("models/phishshield_model.joblib"))
    metrics_output: Path = field(default_factory=lambda: Path("reports/metrics.json"))
