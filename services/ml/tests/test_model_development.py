from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd

from phishshield_ml.model_development import (
    CALIBRATION_METHODS,
    build_pipeline,
    calibrate_model,
    combined_groups,
    grouped_splits,
    load_registry,
    search_model,
    validate_registry,
)


def _entry(estimator: str = "logistic_regression") -> dict:
    return {
        "model_id": "test-v1", "estimator": estimator,
        "hyperparameters": [{"C": 0.5}, {"C": 1.0}],
        "feature_configuration": {"type": "word_tfidf", "lowercase": True, "ngram_range": [1, 2],
                                  "min_df": 1, "max_df": 1.0, "max_features": 100, "selection_k": 8,
                                  "sublinear_tf": True, "strip_accents": "unicode"},
        "calibration_methods": list(CALIBRATION_METHODS), "random_seed": 42,
        "training_manifest_hash": "train", "evaluation_manifest_hashes": {}, "experiment_version": "test-v1",
    }


def _frame() -> pd.DataFrame:
    rows = []
    for group in range(6):
        label = group % 2
        for item in range(2):
            token = "verify password urgent" if label else "meeting project update"
            rows.append({"text": f"{token} group{group} item{item}", "label": label,
                         "campaign_group": f"campaign-{group}", "template_group": f"template-{group}",
                         "source_weight": 1.0})
    return pd.DataFrame(rows)


def test_versioned_registry_is_complete_and_consistent():
    registry, _, _ = load_registry("services/ml/config/models/phase_c_v1.json")
    validate_registry(registry)
    assert len(registry["models"]) == 6
    assert {item["estimator"] for item in registry["models"]} == {
        "logistic_regression", "linear_svm", "sgd_classifier", "complement_naive_bayes",
        "random_forest", "hist_gradient_boosting",
    }
    assert len({json.dumps(item["feature_configuration"], sort_keys=True) for item in registry["models"]}) == 1


def test_campaign_and_template_connected_components_do_not_leak():
    frame = _frame()
    frame.loc[1, "template_group"] = "template-1"
    groups = combined_groups(frame)
    assert groups[0] == groups[2]
    for train, valid in grouped_splits(frame, seed=42, n_splits=3):
        assert not set(frame.iloc[train].campaign_group) & set(frame.iloc[valid].campaign_group)
        assert not set(frame.iloc[train].template_group) & set(frame.iloc[valid].template_group)


def test_search_and_calibration_are_deterministic_and_training_only():
    frame = _frame(); entry = _entry(); splits = grouped_splits(frame, seed=42, n_splits=3)
    first, trials_a = search_model(entry, frame, splits)
    second, trials_b = search_model(entry, frame, splits)
    assert first == second
    assert trials_a == trials_b
    model, comparison = calibrate_model(entry, first, frame, splits)
    assert comparison["selected_method"] in CALIBRATION_METHODS
    assert all(0 <= comparison[name]["brier_score"] <= 1 for name in CALIBRATION_METHODS)
    probability = model.predict_proba(["urgent verify password"])[0, 1]
    assert 0 <= probability <= 1


def test_pipeline_serialization_has_reproducible_predictions(tmp_path):
    frame = _frame(); entry = _entry(); splits = grouped_splits(frame, seed=42, n_splits=3)
    model, _ = calibrate_model(entry, {"C": 1.0}, frame, splits)
    before = model.predict_proba(frame.text)[:, 1]
    path = tmp_path / "candidate.joblib"
    joblib.dump({"model": model, "deployment_candidate": True, "activated": False}, path)
    bundle = joblib.load(path)
    after = bundle["model"].predict_proba(frame.text)[:, 1]
    np.testing.assert_array_equal(before, after)
    assert bundle["deployment_candidate"] is True
    assert bundle["activated"] is False


def test_model_builders_cover_required_estimators():
    parameters = {
        "logistic_regression": {"C": 1.0}, "linear_svm": {"C": 1.0},
        "sgd_classifier": {"alpha": 0.0001}, "complement_naive_bayes": {"alpha": 1.0},
        "random_forest": {"n_estimators": 5, "max_depth": 3},
        "hist_gradient_boosting": {"max_iter": 2, "max_leaf_nodes": 3},
    }
    for estimator, values in parameters.items():
        entry = _entry(estimator)
        assert build_pipeline(entry, values).named_steps["clf"] is not None
