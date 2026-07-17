"""Typed schemas for ML training, evaluation, and inference outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DatasetSummary:
    input_rows: int
    total_rows: int
    legitimate_count: int
    phishing_count: int
    empty_rows_removed: int
    duplicate_rows_removed: int
    near_duplicate_groups: int = 0
    english_count: int = 0
    english_percentage: float = 0.0


@dataclass(frozen=True)
class SplitSummary:
    train_rows: int
    validation_rows: int
    test_rows: int


@dataclass(frozen=True)
class Metrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    confusion_matrix: list[list[int]]
    false_positive_rate: float
    false_negative_rate: float
    pr_auc: float | None = None
    brier_score: float | None = None


@dataclass(frozen=True)
class TrainingSummary:
    model_version: str
    preprocessing_version: str
    dataset_summary: DatasetSummary
    split_summary: SplitSummary
    validation_metrics: Metrics
    test_metrics: Metrics
    selected_threshold: float
    model_path: str
    metadata_path: str


@dataclass(frozen=True)
class ExplainabilityTerm:
    term: str
    contribution: float


@dataclass(frozen=True)
class InferenceResult:
    predicted_label: str
    phishing_probability: float
    legitimate_probability: float
    model_version: str
    top_phishing_terms: list[ExplainabilityTerm] = field(default_factory=list)
    top_legitimate_terms: list[ExplainabilityTerm] = field(default_factory=list)


@dataclass(frozen=True)
class LoadedModelBundle:
    pipeline: Any
    model_version: str
    label_mapping: dict[str, int]
    preprocessing_version: str
    feature_config: dict[str, Any]
    training_timestamp: str
    dataset_summary: dict[str, Any]
    evaluation_metrics: dict[str, Any]
    decision_threshold: float = 0.5
