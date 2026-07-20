"""Deterministic Phase C model comparison on frozen, approved datasets."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from scipy.special import expit
from sklearn.base import clone
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import brier_score_loss
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.svm import LinearSVC

from .weak_label_experiments import (
    boundary_audit,
    canonical_hash,
    error_summary,
    expected_calibration_error,
    load_config as load_boundary_config,
    metrics,
    privacy_scan,
    sha256_file,
)


CALIBRATION_METHODS = ("uncalibrated", "platt", "isotonic")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False), encoding="utf-8")


def load_registry(path: str | Path) -> tuple[dict, Path, Path]:
    registry_path = Path(path).resolve()
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    root = next(parent for parent in registry_path.parents if (parent / "services" / "ml").exists())
    validate_registry(registry)
    return registry, root, registry_path


def validate_registry(registry: dict) -> None:
    required = {"experiment_version", "random_seed", "fixed_threshold", "boundary_config", "models"}
    missing = required - set(registry)
    if missing:
        raise ValueError(f"Model registry missing fields: {sorted(missing)}")
    if registry["fixed_threshold"] != 0.5:
        raise ValueError("Phase C comparison requires the frozen 0.5 threshold")
    ids = [item.get("model_id") for item in registry["models"]]
    if len(ids) != len(set(ids)) or len(ids) < 6:
        raise ValueError("Registry needs at least six unique required model IDs")
    required_model = {"model_id", "estimator", "hyperparameters", "feature_configuration",
                      "calibration_methods", "random_seed", "training_manifest_hash",
                      "evaluation_manifest_hashes", "experiment_version"}
    for item in registry["models"]:
        if required_model - set(item):
            raise ValueError(f"Incomplete model registry entry: {item.get('model_id')}")
        if item["random_seed"] != registry["random_seed"]:
            raise ValueError("Model seed differs from registry seed")
        if tuple(item["calibration_methods"]) != CALIBRATION_METHODS:
            raise ValueError("Every model must compare the same calibration methods")


def _vectorizer(feature: dict) -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=feature["lowercase"], ngram_range=tuple(feature["ngram_range"]),
        min_df=feature["min_df"], max_df=feature["max_df"], max_features=feature["max_features"],
        sublinear_tf=feature["sublinear_tf"], strip_accents=feature["strip_accents"],
    )


def _dense(value: Any) -> np.ndarray:
    return value.toarray() if hasattr(value, "toarray") else np.asarray(value)


def build_pipeline(entry: dict, parameters: dict) -> Pipeline:
    seed = entry["random_seed"]
    name = entry["estimator"]
    if name == "logistic_regression":
        estimator = LogisticRegression(class_weight="balanced", solver="liblinear", max_iter=2000,
                                       random_state=seed, **parameters)
    elif name == "linear_svm":
        estimator = LinearSVC(class_weight="balanced", random_state=seed, max_iter=5000, **parameters)
    elif name == "sgd_classifier":
        estimator = SGDClassifier(class_weight="balanced", random_state=seed, max_iter=3000,
                                  tol=1e-4, loss="log_loss", **parameters)
    elif name == "complement_naive_bayes":
        estimator = ComplementNB(**parameters)
    elif name == "random_forest":
        estimator = RandomForestClassifier(class_weight="balanced", random_state=seed, n_jobs=1,
                                           **parameters)
    elif name == "hist_gradient_boosting":
        estimator = HistGradientBoostingClassifier(random_state=seed, early_stopping=False, **parameters)
    else:
        raise ValueError(f"Unsupported estimator: {name}")
    feature = entry["feature_configuration"]
    steps: list[tuple[str, Any]] = [("features", _vectorizer(feature)),
                                    ("feature_selection", SelectKBest(chi2, k=feature["selection_k"]))]
    if name == "hist_gradient_boosting":
        steps.append(("dense", FunctionTransformer(_dense, accept_sparse=True)))
    steps.append(("clf", estimator))
    return Pipeline(steps)


def combined_groups(frame: pd.DataFrame) -> np.ndarray:
    """Return connected components across campaign and template identifiers."""
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    pairs = []
    for index, row in frame.reset_index(drop=True).iterrows():
        campaign = f"c:{row.get('campaign_group', f'row-{index}')}"
        template = f"t:{row.get('template_group', f'row-{index}')}"
        union(campaign, template)
        pairs.append((campaign, template))
    return np.asarray([find(campaign) for campaign, _ in pairs], dtype=object)


def grouped_splits(frame: pd.DataFrame, seed: int, n_splits: int = 3) -> list[tuple[np.ndarray, np.ndarray]]:
    groups = combined_groups(frame)
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    splits = list(splitter.split(frame.text, frame.label.astype(int), groups))
    for train, valid in splits:
        for field in ("campaign_group", "template_group"):
            if field in frame and set(frame.iloc[train][field].astype(str)) & set(frame.iloc[valid][field].astype(str)):
                raise RuntimeError(f"Grouped CV leaked {field}")
    return splits


def _raw_score(pipeline: Pipeline, texts: Any) -> np.ndarray:
    if hasattr(pipeline, "decision_function"):
        return np.asarray(pipeline.decision_function(texts), dtype=float)
    probability = np.asarray(pipeline.predict_proba(texts)[:, 1], dtype=float)
    return np.log(np.clip(probability, 1e-8, 1 - 1e-8) / np.clip(1 - probability, 1e-8, 1))


def _native_probability(pipeline: Pipeline, texts: Any) -> np.ndarray:
    if hasattr(pipeline, "predict_proba"):
        return np.asarray(pipeline.predict_proba(texts)[:, 1], dtype=float)
    return expit(_raw_score(pipeline, texts))


def _reliability(y: np.ndarray, probability: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0, 1, bins + 1)
    result = []
    for index in range(bins):
        mask = (probability >= edges[index]) & (probability < edges[index + 1] if index < bins - 1 else probability <= 1)
        result.append({"lower": float(edges[index]), "upper": float(edges[index + 1]), "count": int(mask.sum()),
                       "mean_probability": float(probability[mask].mean()) if mask.any() else None,
                       "observed_rate": float(y[mask].mean()) if mask.any() else None})
    return result


@dataclass
class CalibratedModel:
    pipeline: Pipeline
    method: str
    calibrator: Any = None

    def predict_proba(self, texts: Any) -> np.ndarray:
        if self.method == "uncalibrated":
            positive = _native_probability(self.pipeline, texts)
        else:
            score = _raw_score(self.pipeline, texts)
            positive = (self.calibrator.predict_proba(score.reshape(-1, 1))[:, 1]
                        if self.method == "platt" else self.calibrator.predict(score))
        positive = np.clip(np.asarray(positive, dtype=float), 0, 1)
        return np.column_stack((1 - positive, positive))


def _fit_calibrator(method: str, scores: np.ndarray, labels: np.ndarray, seed: int) -> Any:
    if method == "platt":
        return LogisticRegression(random_state=seed, solver="lbfgs").fit(scores.reshape(-1, 1), labels)
    if method == "isotonic":
        return IsotonicRegression(out_of_bounds="clip").fit(scores, labels)
    return None


def _cross_fitted_calibration(method: str, scores: np.ndarray, labels: np.ndarray, seed: int) -> np.ndarray:
    probability = np.zeros(len(labels), dtype=float)
    splitter = StratifiedKFold(n_splits=3, shuffle=True, random_state=seed)
    for train, valid in splitter.split(scores, labels):
        calibrator = _fit_calibrator(method, scores[train], labels[train], seed)
        probability[valid] = (calibrator.predict_proba(scores[valid].reshape(-1, 1))[:, 1]
                              if method == "platt" else calibrator.predict(scores[valid]))
    return probability


def _oof(pipeline: Pipeline, frame: pd.DataFrame, splits: list[tuple[np.ndarray, np.ndarray]],
         sample_weight: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    raw = np.zeros(len(frame)); native = np.zeros(len(frame))
    for train, valid in splits:
        model = clone(pipeline)
        fit_args = {"clf__sample_weight": sample_weight[train]}
        try:
            model.fit(frame.text.iloc[train], frame.label.iloc[train], **fit_args)
        except TypeError:
            model.fit(frame.text.iloc[train], frame.label.iloc[train])
        raw[valid] = _raw_score(model, frame.text.iloc[valid])
        native[valid] = _native_probability(model, frame.text.iloc[valid])
    return raw, native


def _fit_full(pipeline: Pipeline, frame: pd.DataFrame, sample_weight: np.ndarray) -> Pipeline:
    try:
        pipeline.fit(frame.text, frame.label.astype(int), clf__sample_weight=sample_weight)
    except TypeError:
        pipeline.fit(frame.text, frame.label.astype(int))
    return pipeline


def search_model(entry: dict, training: pd.DataFrame, splits: list[tuple[np.ndarray, np.ndarray]]) -> tuple[dict, list[dict]]:
    labels = training.label.astype(int).to_numpy(); weights = training.source_weight.astype(float).to_numpy()
    trials = []
    for trial_index, parameters in enumerate(entry["hyperparameters"], 1):
        pipeline = build_pipeline(entry, parameters)
        raw, probability = _oof(pipeline, training, splits, weights)
        result = metrics(labels, probability, 0.5)
        objective = .45 * (result["f1"] or 0) + .35 * (result["mcc"] or 0) + .20 * (result["pr_auc"] or 0)
        trials.append({"trial": trial_index, "parameters": parameters, "objective": float(objective),
                       "grouped_oof_metrics": result, "raw_score_sha256": hashlib.sha256(raw.tobytes()).hexdigest()})
    best = max(trials, key=lambda row: (row["objective"], -row["trial"]))
    return deepcopy(best["parameters"]), trials


def calibrate_model(entry: dict, parameters: dict, training: pd.DataFrame,
                    splits: list[tuple[np.ndarray, np.ndarray]]) -> tuple[CalibratedModel, dict]:
    labels = training.label.astype(int).to_numpy(); weights = training.source_weight.astype(float).to_numpy()
    pipeline = build_pipeline(entry, parameters)
    raw, native = _oof(pipeline, training, splits, weights)
    comparison = {}
    calibrators = {}
    for method in CALIBRATION_METHODS:
        calibrator = _fit_calibrator(method, raw, labels, entry["random_seed"])
        calibrators[method] = calibrator
        probability = native if method == "uncalibrated" else _cross_fitted_calibration(
            method, raw, labels, entry["random_seed"])
        comparison[method] = {"brier_score": float(brier_score_loss(labels, probability)),
                              "expected_calibration_error": expected_calibration_error(labels, probability),
                              "reliability_curve": _reliability(labels, probability)}
    selected = min(CALIBRATION_METHODS, key=lambda method: (comparison[method]["brier_score"],
                                                            comparison[method]["expected_calibration_error"],
                                                            CALIBRATION_METHODS.index(method)))
    comparison["selected_method"] = selected
    fitted = _fit_full(pipeline, training, weights)
    return CalibratedModel(fitted, selected, calibrators[selected]), comparison


def _safe_error_groups(frame: pd.DataFrame, probability: np.ndarray, threshold: float) -> dict:
    prediction = (probability >= threshold).astype(int)
    result = {}
    for kind in ("fp", "fn"):
        base = error_summary(frame, prediction, kind)
        target = ((frame.label.to_numpy() == 0) & (prediction == 1)) if kind == "fp" else ((frame.label.to_numpy() == 1) & (prediction == 0))
        rows = frame.loc[target]
        indicators = {
            "sender_mismatch": r"sender|from:|reply.to|mismatch|spoof",
            "authentication": r"spf|dkim|dmarc|authentication",
            "url_indicators": r"https?://|www\.|<url|href=|link",
            "lexical_indicators": r"urgent|verify|password|account|invoice|payment|click|suspend",
        }
        base["requested_indicator_groups"] = {name: int(rows.text.astype(str).str.contains(pattern, case=False, regex=True).sum())
                                              for name, pattern in indicators.items()}
        base["phishing_family"] = base["grouped_counts"].get("scenario", {})
        result["false_positives" if kind == "fp" else "false_negatives"] = base
    return result


def _feature_importance(model: CalibratedModel, limit: int = 40) -> dict:
    features = model.pipeline.named_steps["features"].get_feature_names_out()
    features = features[model.pipeline.named_steps["feature_selection"].get_support()]
    classifier = model.pipeline.named_steps["clf"]
    if hasattr(classifier, "coef_"):
        values = np.asarray(classifier.coef_).reshape(-1)
    elif hasattr(classifier, "feature_importances_"):
        values = np.asarray(classifier.feature_importances_)
    else:
        return {"available": False, "reason": "estimator_has_no_native_feature_importance", "raw_content_included": False}
    ordered = np.argsort(np.abs(values))[-limit:][::-1]
    family_patterns = {
        "url_indicators": r"url|http|www|href|link", "authentication": r"spf|dkim|dmarc|auth",
        "credential": r"password|credential|login|verify|account", "payment": r"invoice|payment|bank|money",
        "urgency": r"urgent|immediate|suspend|expire", "workplace": r"meeting|project|team|review",
    }
    family_importance = {name: 0.0 for name in (*family_patterns, "other")}
    for feature_name, value in zip(features, values, strict=True):
        family = next((name for name, pattern in family_patterns.items()
                       if re.search(pattern, str(feature_name), re.I)), "other")
        family_importance[family] += abs(float(value))
    return {"available": True, "method": "native_coefficient_or_importance", "features": [
        {"feature_id": hashlib.sha256(str(features[i]).encode()).hexdigest()[:16], "importance": float(values[i]),
         "direction": "phishing" if values[i] >= 0 else "legitimate"} for i in ordered],
        "family_absolute_importance": family_importance, "feature_names_redacted": True, "raw_content_included": False}


def _rank(model_metrics: dict) -> list[dict]:
    raw = []
    for model_id, sets in model_metrics.items():
        external = sets["external_evaluation"]; shift = sets["template_shift_diagnostic"]
        components = {
            "external_recall": external["recall"] or 0, "external_precision": external["precision"] or 0,
            "false_positive_control": 1 - (external["false_positive_rate"] or 0), "mcc": ((external["mcc"] or 0) + 1) / 2,
            "pr_auc": external["pr_auc"] or 0, "calibration": 1 - external["brier_score"],
            "template_shift_robustness": shift["f1"] or 0,
        }
        weights = {"external_recall": .25, "external_precision": .20, "false_positive_control": .15,
                   "mcc": .12, "pr_auc": .10, "calibration": .08, "template_shift_robustness": .10}
        score = sum(weights[key] * value for key, value in components.items())
        raw.append({"model_id": model_id, "weighted_score": float(score), "components": components, "weights": weights})
    raw.sort(key=lambda row: (-row["weighted_score"], row["model_id"]))
    for index, row in enumerate(raw, 1): row["rank"] = index
    return raw


def run_phase_c(registry_path: str | Path, *, force: bool = False) -> dict:
    registry, root, source_path = load_registry(registry_path)
    boundary_config, boundary_root, _ = load_boundary_config(root / registry["boundary_config"])
    audit, baseline, _, evaluations = boundary_audit(boundary_config, boundary_root)
    expected_train = registry["models"][0]["training_manifest_hash"]
    if audit["baseline_training_manifest_sha256"] != expected_train:
        raise RuntimeError("Frozen training manifest differs from model registry")
    if audit["evaluation_manifest_sha256"] != registry["models"][0]["evaluation_manifest_hashes"]:
        raise RuntimeError("Frozen evaluation manifests differ from model registry")
    report_dir = root / registry["report_dir"]; artifact_dir = root / registry["artifact_dir"]
    if (report_dir / "deployment_candidate.json").exists() and not force:
        raise FileExistsError("Completed Phase C run exists; use --force to replace ignored experiment artifacts")

    training = baseline.copy()
    training["source_weight"] = 1.0
    training["campaign_group"] = training.get("campaign_group", training.template_group)
    splits = grouped_splits(training, registry["random_seed"], registry.get("cv_folds", 3))
    fold_manifest = [{"fold": i + 1, "train_rows": len(train), "validation_rows": len(valid),
                      "train_membership_sha256": canonical_hash(sorted(training.iloc[train]._text_hash.astype(str))),
                      "validation_membership_sha256": canonical_hash(sorted(training.iloc[valid]._text_hash.astype(str)))}
                     for i, (train, valid) in enumerate(splits)]
    searches = {}; calibration = {}; fitted = {}; all_metrics = {}; errors = {}
    for entry in registry["models"]:
        parameters, trials = search_model(entry, training, splits)
        searches[entry["model_id"]] = {"best_hyperparameters": parameters, "trials": trials}
        model, calibration_result = calibrate_model(entry, parameters, training, splits)
        fitted[entry["model_id"]] = model; calibration[entry["model_id"]] = calibration_result
        all_metrics[entry["model_id"]] = {}
        errors[entry["model_id"]] = {}
        for name, frame in evaluations.items():
            probability = model.predict_proba(frame.text.astype(str))[:, 1]
            all_metrics[entry["model_id"]][name] = metrics(frame.label.astype(int), probability, registry["fixed_threshold"])
            errors[entry["model_id"]][name] = _safe_error_groups(frame, probability, registry["fixed_threshold"])

    ranking = _rank(all_metrics); best_id = ranking[0]["model_id"]; best = fitted[best_id]
    best_entry = next(item for item in registry["models"] if item["model_id"] == best_id)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    bundle = {"model": best, "decision_threshold": registry["fixed_threshold"], "model_id": best_id,
              "deployment_candidate": True, "activated": False, "experiment_version": registry["experiment_version"]}
    joblib.dump(bundle, artifact_dir / "fitted_pipeline.joblib")
    joblib.dump(best.pipeline.named_steps["features"], artifact_dir / "vectorizer.joblib")
    vectorizer_dimensions = int(len(best.pipeline.named_steps["features"].get_feature_names_out()))
    feature_manifest = {"configuration": best_entry["feature_configuration"],
                        "vectorizer_dimensions": vectorizer_dimensions,
                        "selected_dimensions": int(best_entry["feature_configuration"]["selection_k"]),
                        "configuration_sha256": canonical_hash(best_entry["feature_configuration"])}
    preprocessing_manifest = {"text_input": "existing privacy-sanitized text", "lowercase": True,
                              "strip_accents": "unicode", "dataset_changes": False}
    calibration_metadata = {"method": best.method, "training_only_grouped_oof": True,
                            "comparison": calibration[best_id]}
    model_metadata = {"model_id": best_id, "estimator": best_entry["estimator"],
                      "hyperparameters": searches[best_id]["best_hyperparameters"], "random_seed": registry["random_seed"],
                      "threshold": registry["fixed_threshold"], "deployment_candidate": True, "activated": False,
                      "training_manifest_hash": expected_train, "evaluation_manifest_hashes": audit["evaluation_manifest_sha256"]}
    for name, value in (("feature_manifest.json", feature_manifest), ("preprocessing_manifest.json", preprocessing_manifest),
                        ("calibration_metadata.json", calibration_metadata), ("model_metadata.json", model_metadata)):
        _write_json(artifact_dir / name, value)
    artifact_hash = sha256_file(artifact_dir / "fitted_pipeline.joblib")
    generated = datetime.now(timezone.utc).isoformat()
    training_summary = {"experiment_version": registry["experiment_version"], "generated_at": generated,
                        "training_rows": len(training), "weak_label_policy": "baseline_weak_rows_0",
                        "fixed_threshold": registry["fixed_threshold"], "random_seed": registry["random_seed"],
                        "grouped_cv": {"folds": len(splits), "campaign_aware": True, "template_aware": True,
                                       "fold_manifest": fold_manifest}, "boundary_audit": audit}
    deployment = {"model_id": best_id, "deployment_candidate": True, "activated": False,
                  "artifact_path": str((artifact_dir / "fitted_pipeline.joblib").relative_to(root)),
                  "artifact_sha256": artifact_hash, "production_artifact_overwritten": False,
                  "selection_basis": "weighted protected-set comparison after training-only model fitting and calibration"}
    importance = _feature_importance(best)
    _write_json(report_dir / "training_summary.json", training_summary)
    _write_json(report_dir / "hyperparameter_results.json", searches)
    _write_json(report_dir / "calibration_summary.json", calibration)
    _write_json(report_dir / "model_metrics.json", all_metrics)
    _write_json(report_dir / "model_ranking.json", {"ranking": ranking, "selected_model_id": best_id})
    _write_json(report_dir / "error_analysis.json", errors)
    _write_json(report_dir / "feature_importance.json", importance)
    _write_json(report_dir / "deployment_candidate.json", deployment)
    lines = ["# Phase C Model Comparison", "", f"Generated: {generated}", "", "Fixed threshold: `0.5`. Hyperparameters and calibration were selected using grouped training folds only.", "",
             "| Rank | Model | Score | External precision | External recall | External MCC | External PR-AUC | External FPR | Template-shift F1 |", "|---:|---|---:|---:|---:|---:|---:|---:|---:|"]
    for row in ranking:
        m = all_metrics[row["model_id"]]["external_evaluation"]; s = all_metrics[row["model_id"]]["template_shift_diagnostic"]
        lines.append(f"| {row['rank']} | {row['model_id']} | {row['weighted_score']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['mcc']:.4f} | {m['pr_auc']:.4f} | {m['false_positive_rate']:.4f} | {s['f1']:.4f} |")
    lines += ["", f"Deployment candidate: `{best_id}` (frozen, not activated).", "", "Recommendation: evaluate the frozen candidate operationally before any deployment; Phase C performed no deployment.", ""]
    (report_dir / "model_comparison.md").write_text("\n".join(lines), encoding="utf-8")
    scan = privacy_scan(report_dir)
    return {"selected_model_id": best_id, "ranking": ranking, "deployment_candidate": deployment,
            "privacy_scan": scan, "registry_path": str(source_path)}
