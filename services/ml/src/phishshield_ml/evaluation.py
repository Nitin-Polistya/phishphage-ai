"""Model evaluation helpers for the ML baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .schemas import Metrics


def evaluate_predictions(y_true: Iterable[int], y_pred: Iterable[int], y_proba: Iterable[float] | None = None) -> Metrics:
    true_values = list(y_true)
    pred_values = list(y_pred)
    accuracy = accuracy_score(true_values, pred_values)
    precision = precision_score(true_values, pred_values, zero_division=0)
    recall = recall_score(true_values, pred_values, zero_division=0)
    f1 = f1_score(true_values, pred_values, zero_division=0)
    matrix = confusion_matrix(true_values, pred_values, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    roc_auc = None
    pr_auc = None
    brier = None
    if y_proba is not None and len(set(true_values)) == 2:
        probability_values = list(y_proba)
        try:
            roc_auc = float(roc_auc_score(true_values, probability_values))
            pr_auc = float(average_precision_score(true_values, probability_values))
            brier = float(brier_score_loss(true_values, probability_values))
        except ValueError:
            roc_auc = None
    return Metrics(
        accuracy=float(accuracy),
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        roc_auc=roc_auc,
        confusion_matrix=matrix.astype(int).tolist(),
        false_positive_rate=float(fpr),
        false_negative_rate=float(fnr),
        pr_auc=pr_auc,
        brier_score=brier,
    )


def evaluate_thresholds(y_true: Iterable[int], y_proba: Iterable[float], thresholds: Iterable[float]) -> list[dict]:
    true_values = list(y_true)
    proba_values = list(y_proba)
    results = []
    for threshold in thresholds:
        predictions = [1 if prob >= threshold else 0 for prob in proba_values]
        metrics = evaluate_predictions(true_values, predictions, proba_values)
        results.append({"threshold": float(threshold), **metrics.__dict__})
    return results


def write_metrics_json(metrics: dict, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2, sort_keys=True)
