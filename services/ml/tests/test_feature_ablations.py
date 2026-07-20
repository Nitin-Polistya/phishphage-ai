"""Synthetic safety and correctness checks for Phase B.3F ablations."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from phishshield_ml.feature_ablations import (
    DATA_TREATMENTS,
    FAMILIES,
    REQUIRED_ABLATIONS,
    canonical_hash,
    classification_metrics,
    grouped_source_probe_splits,
    load_registry,
    paired_bootstrap,
    robustness_decision,
    selected_families,
    sanitize_text,
    validate_registry,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config" / "experiments" / "phishing_pot_feature_ablation_v1.json"


def registry() -> dict:
    return load_registry(REGISTRY_PATH)


def test_registry_has_complete_unique_feature_coverage_and_required_ablations():
    config = registry()
    validate_registry(config)
    assert tuple(config["feature_families"]) == FAMILIES
    features = [item for values in config["feature_families"].values() for item in values]
    assert len(features) == len(set(features))
    assert set(config["ablations"]) == set(REQUIRED_ABLATIONS)
    assert set(config["data_treatments"]) == set(DATA_TREATMENTS)


def test_ablation_family_selection_matches_contract():
    config = registry()
    assert selected_families(config, "text_only") == ("lexical_text",)
    assert selected_families(config, "semantic_indicators_only") == ("semantic_security_indicators",)
    assert set(selected_families(config, "structured_only")) == set(FAMILIES) - {"lexical_text"}
    assert set(selected_families(config, "without_sender_infrastructure")) == set(FAMILIES) - {"sender_infrastructure"}
    assert set(selected_families(config, "baseline_full")) == set(FAMILIES)


def test_registry_rejects_duplicate_and_prohibited_features():
    duplicate = registry()
    duplicate["feature_families"]["metadata_misc"].append("spf")
    with pytest.raises(ValueError, match="multiple families"):
        validate_registry(duplicate)

    prohibited = registry()
    prohibited["feature_families"]["metadata_misc"].append("full_url")
    with pytest.raises(ValueError, match="Prohibited"):
        validate_registry(prohibited)


def test_registry_rejects_unknown_ablation_family_and_threshold_drift():
    config = registry()
    config["ablations"]["text_only"]["include"] = ["unknown_family"]
    with pytest.raises(ValueError):
        validate_registry(config)
    config = registry()
    config["fixed_threshold"] = 0.4
    with pytest.raises(ValueError, match="threshold"):
        validate_registry(config)


def test_frozen_model_and_weight_configuration():
    config = registry()
    model = config["model_configuration"]
    assert model["type"] == "logistic_regression"
    assert model["class_weight"] == "balanced"
    assert model["random_state"] == config["seed"]
    assert config["data_treatments"]["baseline"] == {"weak_rows": 0, "weak_weight": None}
    assert config["data_treatments"]["weak_035"] == {"weak_rows": 107, "weak_weight": 0.35}
    assert config["data_treatments"]["weak_050"] == {"weak_rows": 107, "weak_weight": 0.5}
    assert config["fixed_threshold"] == 0.5


def test_metrics_confusion_undefined_and_calibration_are_explicit():
    result = classification_metrics([0, 0, 1, 1], [0.1, 0.8, 0.9, 0.2])
    assert result["confusion_matrix"] == [[1, 1], [1, 1]]
    assert result["false_positives"] == result["false_negatives"] == 1
    assert 0 <= result["brier_score"] <= 1
    single = classification_metrics([0, 0], [0.1, 0.2])
    assert single["roc_auc"] is None
    assert single["pr_auc"] is None
    assert single["mcc"] is None


def test_paired_bootstrap_is_deterministic_and_paired():
    y = [0, 1, 0, 1, 1]
    left = [0.1, 0.4, 0.2, 0.6, 0.3]
    right = [0.1, 0.8, 0.2, 0.9, 0.7]
    first = paired_bootstrap(y, left, right, iterations=40, seed=17)
    assert first == paired_bootstrap(y, left, right, iterations=40, seed=17)
    assert first["iterations"] == 40
    assert first["ci95"] is not None


def test_grouped_probe_folds_keep_campaigns_together():
    groups = ["campaign-a", "campaign-a", "campaign-b", "campaign-b", "campaign-c", "campaign-d"]
    folds = grouped_source_probe_splits(groups, n_splits=3, seed=9)
    assert len(folds) == 3
    for train, test in folds:
        assert not set(train.nonzero()[0]).intersection(test.nonzero()[0])
        for group in set(groups):
            indices = [i for i, value in enumerate(groups) if value == group]
            assert len({bool(train[i]) for i in indices}) == 1


def test_ablation_sanitization_masks_disabled_infrastructure_but_keeps_semantics():
    text = "Urgent password reset https://evil.example/login from attacker@evil.example"
    masked = sanitize_text(text, ("lexical_text", "semantic_security_indicators"))
    assert "password" in masked.lower()
    assert "urgent" in masked.lower()
    assert "evil.example" not in masked
    assert "attacker@evil.example" not in masked


def test_robustness_policy_is_explicit_and_never_activates():
    policy = registry()["policy"]
    baseline = {"recall": 0.8, "false_positive_rate": 0.01, "brier_score": 0.10}
    candidate = {"recall": 0.79, "false_positive_rate": 0.02, "brier_score": 0.11}
    result = robustness_decision(baseline, candidate, policy)
    assert result["robust"] is True
    assert result["activation_performed"] is False
    failing = robustness_decision(baseline, {"recall": 0.5, "false_positive_rate": 0.5, "brier_score": 0.5}, policy)
    assert failing["robust"] is False
    assert failing["activation_performed"] is False


def test_registry_hash_is_deterministic_and_artifact_paths_are_isolated():
    config = registry()
    assert canonical_hash(config) == canonical_hash(json.loads(json.dumps(config)))
    artifact = config["paths"]["artifact_dir"].replace("\\", "/")
    assert "artifacts/experiments/phishing_pot_feature_ablation_v1" in artifact
    assert "active" not in artifact.lower()
    assert config["fixed_threshold"] == 0.5
