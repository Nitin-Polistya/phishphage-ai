from __future__ import annotations

from phishshield_ml.weak_label_experiments import (
    EXPERIMENT_IDS,
    bootstrap_pair,
    metrics,
    validate_config,
)


def test_frozen_experiment_definitions_and_threshold():
    config = {
        "seed": 42,
        "fixed_threshold": 0.5,
        "experiments": {
            "baseline": {"weak_rows": 0, "weak_weight": None},
            "weak_035": {"weak_rows": 107, "weak_weight": 0.35},
            "weak_050": {"weak_rows": 107, "weak_weight": 0.5},
        },
        "model_configuration": {"random_state": 42},
    }
    validate_config(config)
    assert EXPERIMENT_IDS == ("baseline", "weak_035", "weak_050")


def test_config_rejects_threshold_or_experiment_drift():
    config = {
        "seed": 42,
        "fixed_threshold": 0.4,
        "experiments": {
            "baseline": {"weak_rows": 0, "weak_weight": None},
            "weak_035": {"weak_rows": 107, "weak_weight": 0.35},
            "weak_050": {"weak_rows": 107, "weak_weight": 0.5},
        },
        "model_configuration": {"random_state": 42},
    }
    try:
        validate_config(config)
    except ValueError as exc:
        assert "threshold" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("threshold drift must be rejected")


def test_metrics_confusion_and_calibration_are_explicit():
    result = metrics([0, 0, 1, 1], [0.1, 0.8, 0.9, 0.2], 0.5)
    assert (
        result["true_negatives"],
        result["false_positives"],
        result["false_negatives"],
        result["true_positives"],
    ) == (1, 1, 1, 1)
    assert result["false_negatives"] == 1
    assert 0 <= result["brier_score"] <= 1
    assert 0 <= result["expected_calibration_error"] <= 1


def test_metrics_handles_single_class_without_silent_zeroes():
    result = metrics([0, 0], [0.1, 0.2], 0.5)
    assert result["roc_auc"] is None
    assert result["pr_auc"] is None
    assert result["mcc"] is None
    assert result["undefined_metrics_are_null"] is True


def test_bootstrap_comparison_is_deterministic():
    left = {"y": [0, 1, 0, 1], "probability": [0.1, 0.4, 0.2, 0.6]}
    right = {"y": [0, 1, 0, 1], "probability": [0.1, 0.8, 0.2, 0.9]}
    first = bootstrap_pair(left, right, iterations=50, seed=123)
    second = bootstrap_pair(left, right, iterations=50, seed=123)
    assert first == second
    assert first["recall"]["point_delta_right_minus_left"] >= 0
