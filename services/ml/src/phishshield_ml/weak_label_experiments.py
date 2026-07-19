"""Isolated, fixed-threshold weak-label experiments for Phishing Pot Batch 002."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import platform
import re
import runpy
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             brier_score_loss, confusion_matrix, f1_score,
                             log_loss, matthews_corrcoef, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline

EXPERIMENT_IDS = ("baseline", "weak_035", "weak_050")
WEAK_SOURCE = "github_rf_peixoto_phishing_pot"
FORBIDDEN_REPORT_PATTERNS = (
    re.compile(r"https?://", re.I),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    re.compile(r"\bMessage-ID\s*:", re.I),
    re.compile(r"\bReceived\s*:", re.I),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def load_config(path: str | Path) -> tuple[dict, Path, Path]:
    config_path = Path(path).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    root = next(parent for parent in config_path.parents if (parent / "services" / "ml").exists())
    validate_config(config)
    return config, root, config_path


def validate_config(config: dict) -> None:
    if tuple(config.get("experiments", {})) != EXPERIMENT_IDS:
        raise ValueError("Exactly baseline, weak_035, and weak_050 must be configured in that order")
    expected = {"baseline": (0, None), "weak_035": (107, .35), "weak_050": (107, .5)}
    for name, values in expected.items():
        item = config["experiments"][name]
        if (item["weak_rows"], item["weak_weight"]) != values:
            raise ValueError(f"Invalid frozen definition for {name}")
    if config.get("fixed_threshold") != .5:
        raise ValueError("This suite requires the frozen 0.50 threshold")
    if config["model_configuration"].get("random_state") != config.get("seed"):
        raise ValueError("Model and suite seed differ")
    expected_hashes = config.get("expected_sha256", {})
    if expected_hashes.get("feature_configuration") and expected_hashes["feature_configuration"] != canonical_hash(config["feature_configuration"]):
        raise ValueError("Feature configuration hash does not match frozen hash")
    if expected_hashes.get("model_configuration") and expected_hashes["model_configuration"] != canonical_hash(config["model_configuration"]):
        raise ValueError("Model configuration hash does not match frozen hash")


def _read_weak(path: Path) -> pd.DataFrame:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return pd.DataFrame(rows)


def _read_hard_negatives(path: Path) -> pd.DataFrame:
    namespace = runpy.run_path(str(path))
    rows = []
    for index, (scenario, subject, body) in enumerate(namespace["HARD_NEGATIVES"]):
        rows.append({"text": f"Subject: {subject}\n\n{body}", "label": 0,
                     "source": "tracked_synthetic_hard_negative", "scenario": scenario,
                     "template_group": f"hard-negative-{index}"})
    return pd.DataFrame(rows)


def _load_evaluations(config: dict, root: Path) -> dict[str, pd.DataFrame]:
    result = {}
    for name, relative in config["evaluation"].items():
        path = root / relative
        result[name] = _read_hard_negatives(path) if name == "hard_negative" else pd.read_csv(path)
        result[name]["text"] = result[name]["text"].fillna("").astype(str).str.strip()
        result[name]["label"] = result[name]["label"].astype(int)
    return result


def boundary_audit(config: dict, root: Path) -> tuple[dict, pd.DataFrame, pd.DataFrame, dict[str, pd.DataFrame]]:
    paths = config["paths"]
    expected = config["expected_sha256"]
    checked = {}
    file_map = {"baseline": paths["baseline"], "weak_manifest": paths["weak_manifest"], **config["evaluation"]}
    for key, relative in file_map.items():
        actual = sha256_file(root / relative)
        checked[key] = actual
        if actual != expected[key]:
            raise RuntimeError(f"Frozen hash mismatch for {key}: {actual}")

    baseline_original = pd.read_csv(root / paths["baseline"])
    baseline_original["text"] = baseline_original["text"].fillna("").astype(str).str.strip()
    weak = _read_weak(root / paths["weak_manifest"])
    evaluations = _load_evaluations(config, root)
    if len(weak) != 107 or weak["sample_id"].nunique() != 107:
        raise RuntimeError("Weak manifest must contain exactly 107 unique rows")
    if WEAK_SOURCE in set(baseline_original.get("source", pd.Series(dtype=str)).astype(str)):
        raise RuntimeError("Baseline contains weak-source rows")
    required = {"label_quality", "review_status", "split_role", "campaign_group", "template_group", "source_id", "privacy_status"}
    if not required.issubset(weak.columns):
        raise RuntimeError(f"Weak manifest missing fields: {sorted(required - set(weak.columns))}")
    invalid = weak.loc[(weak.label != "phishing") | (weak.label_quality != "weak_source_provenance") |
                       (weak.review_status != "not_manually_reviewed") | (weak.split_role != "train_only") |
                       (weak.source_id != WEAK_SOURCE) | (weak.privacy_status != "privacy_sanitized")]
    if len(invalid):
        raise RuntimeError("Weak manifest violates eligibility or train-only constraints")

    eval_hashes = set().union(*({text_hash(v) for v in frame.text} for frame in evaluations.values()))
    eval_templates = set().union(*(set(frame.get("template_group", pd.Series(dtype=str)).dropna().astype(str)) for frame in evaluations.values()))
    baseline_original["_text_hash"] = baseline_original.text.map(text_hash)
    overlap_mask = baseline_original._text_hash.isin(eval_hashes)
    group_mask = baseline_original.get("template_group", pd.Series(index=baseline_original.index, dtype=str)).astype(str).isin(eval_templates)
    excluded = baseline_original.loc[overlap_mask | group_mask].copy()
    baseline = baseline_original.loc[~(overlap_mask | group_mask)].copy().reset_index(drop=True)
    train_hashes = set(baseline._text_hash) | {text_hash(v) for v in weak.text}
    if train_hashes & eval_hashes:
        raise RuntimeError("Training/evaluation text overlap remains")
    weak_groups = set(weak.campaign_group.astype(str)) | set(weak.template_group.astype(str))
    if weak_groups & eval_templates:
        raise RuntimeError("Weak campaign/template group crosses a protected boundary")
    if weak.sample_id.duplicated().any() or weak.text.map(text_hash).duplicated().any():
        raise RuntimeError("Weak row identity is not unique")

    baseline_manifest = canonical_hash(sorted(baseline._text_hash.tolist()))
    weak_manifest = canonical_hash(sorted(weak.sample_id.astype(str).tolist()))
    evaluation_manifests = {name: canonical_hash(sorted((text_hash(row.text), int(row.label)) for row in frame.itertuples()))
                            for name, frame in evaluations.items()}
    audit = {
        "status": "passed", "privacy_safe": True, "frozen_file_sha256": checked,
        "feature_configuration_sha256": canonical_hash(config["feature_configuration"]),
        "model_configuration_sha256": canonical_hash(config["model_configuration"]),
        "baseline_training_manifest_sha256": baseline_manifest,
        "weak_identity_manifest_sha256": weak_manifest,
        "evaluation_manifest_sha256": evaluation_manifests,
        "baseline_source_rows": int(len(baseline_original)),
        "baseline_rows_after_protected_boundary_exclusion": int(len(baseline)),
        "baseline_rows_excluded_for_exact_overlap": int(overlap_mask.sum()),
        "baseline_rows_excluded_for_template_boundary": int(group_mask.sum()),
        "weak_rows": int(len(weak)), "remaining_training_evaluation_overlap": 0,
        "weak_rows_outside_training": 0, "weak_group_boundary_crossings": 0,
        "note": "Protected template-shift rows present in the historical source CSV are excluded identically from all experiment training sets."
    }
    return audit, baseline, weak, evaluations


def materialize(experiment: str, config: dict, baseline: pd.DataFrame, weak: pd.DataFrame, output: Path) -> tuple[pd.DataFrame, dict]:
    base = baseline.copy()
    base["sample_id"] = base["_text_hash"].map(lambda value: f"approved-{value[:20]}")
    base["source_id"] = base.get("source", "approved_existing")
    base["label_quality"] = base.get("provenance_type", "approved_existing").fillna("approved_existing")
    base["review_status"] = "existing_approved_corpus"
    base["privacy_status"] = "existing_approved_corpus"
    base["campaign_group"] = base.get("campaign_group", base.get("template_group", base.sample_id))
    base["split_role"] = "train_only"
    base["source_weight"] = 1.0
    columns = ["sample_id", "text", "label", "source_id", "label_quality", "review_status", "privacy_status",
               "campaign_group", "template_group", "split_role", "source_weight"]
    base = base[columns]
    if experiment == "baseline":
        frame = base
    else:
        weight = config["experiments"][experiment]["weak_weight"]
        addition = weak.copy()
        addition["label"] = 1
        addition["source_weight"] = weight
        frame = pd.concat([base, addition[columns]], ignore_index=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    membership = canonical_hash(sorted(frame.sample_id.astype(str)))
    non_weight = canonical_hash(sorted((row.sample_id, int(row.label), row.source_id) for row in frame.itertuples()))
    return frame, {"rows": len(frame), "membership_sha256": membership, "non_weight_sha256": non_weight,
                   "dataset_sha256": sha256_file(output), "effective_weight": float(frame.source_weight.sum())}


def build_pipeline(config: dict) -> Pipeline:
    feature = config["feature_configuration"]
    model = config["model_configuration"]
    return Pipeline([
        ("features", TfidfVectorizer(lowercase=feature["lowercase"], ngram_range=tuple(feature["ngram_range"]),
                                     min_df=feature["min_df"], max_df=feature["max_df"],
                                     max_features=feature["max_features"], sublinear_tf=feature["sublinear_tf"],
                                     strip_accents=feature["strip_accents"])),
        ("clf", LogisticRegression(class_weight=model["class_weight"], solver=model["solver"],
                                   max_iter=model["max_iter"], random_state=model["random_state"]))])


def expected_calibration_error(y: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    total = len(y)
    if total == 0:
        return math.nan
    result = 0.0
    edges = np.linspace(0, 1, bins + 1)
    for index in range(bins):
        mask = (probability >= edges[index]) & (probability < edges[index + 1] if index < bins - 1 else probability <= 1)
        if mask.any():
            result += mask.mean() * abs(float(y[mask].mean()) - float(probability[mask].mean()))
    return float(result)


def metrics(y_value: Any, probability_value: Any, threshold: float) -> dict:
    y = np.asarray(y_value, dtype=int); probability = np.asarray(probability_value, dtype=float)
    prediction = (probability >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    both_y = len(np.unique(y)) == 2
    both_p = len(np.unique(prediction)) == 2
    def ratio(a: int, b: int) -> float | None: return float(a / b) if b else None
    return {
        "rows": int(len(y)), "class_balance": {"legitimate": int((y == 0).sum()), "phishing": int((y == 1).sum())},
        "true_positives": int(tp), "true_negatives": int(tn), "false_positives": int(fp), "false_negatives": int(fn),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "specificity": ratio(tn, tn + fp),
        # Keep explicit error-rate fields in every report.  Consumers should not
        # have to derive FPR/FNR from specificity/recall (and null is preferable
        # to an invented zero when a class is absent).
        "false_positive_rate": ratio(fp, tn + fp),
        "false_negative_rate": ratio(fn, fn + tp),
        "accuracy": ratio(tn + tp, len(y)),
        "f1": float(f1_score(y, prediction)) if tp + fp + fn else None,
        "balanced_accuracy": float(balanced_accuracy_score(y, prediction)) if both_y else None,
        "mcc": float(matthews_corrcoef(y, prediction)) if both_y and both_p else None,
        "roc_auc": float(roc_auc_score(y, probability)) if both_y else None,
        "pr_auc": float(average_precision_score(y, probability)) if both_y else None,
        "log_loss": float(log_loss(y, probability, labels=[0, 1])), "brier_score": float(brier_score_loss(y, probability)),
        "expected_calibration_error": expected_calibration_error(y, probability),
        "mean_probability_by_class": {"legitimate": float(probability[y == 0].mean()) if (y == 0).any() else None,
                                      "phishing": float(probability[y == 1].mean()) if (y == 1).any() else None},
        "undefined_metrics_are_null": True,
    }


def _safe_tags(text: str) -> list[str]:
    lower = text.lower()
    groups = {"credential_request": r"password|credential|login|sign.in", "account_security": r"account|security|suspend",
              "invoice_payment": r"invoice|payment|bank|money", "qr_mfa": r"\bqr\b|\bmfa\b|otp|code",
              "delivery": r"delivery|package|shipment", "url_indicator": r"https?://|www\.|<url",
              "html_formatting": r"<html|<a\s|href=", "workplace_project": r"project|meeting|review|team|repository"}
    return [name for name, pattern in groups.items() if re.search(pattern, lower)] or ["other"]


def error_summary(frame: pd.DataFrame, prediction: np.ndarray, kind: str) -> dict:
    target = (frame.label.to_numpy() == 1) & (prediction == 0) if kind == "fn" else (frame.label.to_numpy() == 0) & (prediction == 1)
    rows = frame.loc[target]
    tags = Counter(tag for text in rows.text for tag in _safe_tags(text))
    fields = ["scenario", "campaign_group", "template_group", "source"]
    grouped = {}
    for field in fields:
        if field in rows:
            values = rows[field].fillna("unknown").astype(str)
            # Only aggregate categories; hash campaign/template identifiers.
            if field in {"campaign_group", "template_group", "scenario"}:
                values = values.map(lambda value: f"group-{hashlib.sha256(value.encode()).hexdigest()[:12]}")
            grouped[field] = dict(Counter(values).most_common(20))
    return {"count": int(target.sum()), "indicator_groups": dict(tags), "grouped_counts": grouped,
            "raw_content_included": False, "addresses_or_urls_included": False}


def train_and_evaluate(experiment: str, config: dict, root: Path, training: pd.DataFrame,
                       evaluations: dict[str, pd.DataFrame], artifact_dir: Path) -> tuple[dict, dict, dict, dict]:
    pipeline = build_pipeline(config)
    pipeline.fit(training.text.astype(str), training.label.astype(int), clf__sample_weight=training.source_weight.astype(float))
    threshold = config["fixed_threshold"]
    all_metrics = {}; predictions = {}; fn = {}; fp = {}
    for name, frame in evaluations.items():
        probability = pipeline.predict_proba(frame.text.astype(str))[:, 1]
        prediction = (probability >= threshold).astype(int)
        all_metrics[name] = metrics(frame.label, probability, threshold)
        predictions[name] = {"y": frame.label.astype(int).tolist(), "probability": probability.tolist()}
        fn[name] = error_summary(frame, prediction, "fn")
        fp[name] = error_summary(frame, prediction, "fp")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    bundle = {"pipeline": pipeline, "threshold": threshold, "experimental_only": True,
              "deployment_allowed": False, "experiment_id": experiment}
    joblib.dump(bundle, artifact_dir / "model.joblib")
    feature_dimensions = int(len(pipeline.named_steps["features"].get_feature_names_out()))
    metadata = {"experiment_id": experiment, "experimental_only": True, "deployment_allowed": False,
                "fixed_threshold": threshold, "feature_dimensions": feature_dimensions,
                "model_sha256": sha256_file(artifact_dir / "model.joblib")}
    (artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return all_metrics, predictions, fn, fp


def source_shortcut(models: dict[str, Pipeline], baseline: pd.DataFrame, weak: pd.DataFrame, config: dict) -> tuple[dict, dict]:
    shifts = {}; coefficients = {}
    for name, model in models.items():
        names = model.named_steps["features"].get_feature_names_out()
        coef = model.named_steps["clf"].coef_[0]
        coefficients[name] = dict(zip(names, coef))
    base = coefficients["baseline"]
    for experiment in ("weak_035", "weak_050"):
        delta = [(feature, value - base.get(feature, 0.0)) for feature, value in coefficients[experiment].items()]
        delta.sort(key=lambda item: abs(item[1]), reverse=True)
        shifts[experiment] = [{"feature_id": hashlib.sha256(feature.encode()).hexdigest()[:16], "absolute_delta": abs(float(value)),
                               "source_artifact_pattern": bool(re.search(r"honeypot|phishing.?pot|message.?id|received", feature, re.I))}
                              for feature, value in delta[:30]]
    gold_phish = baseline.loc[baseline.label.astype(int).eq(1), "text"].astype(str)
    x = pd.concat([gold_phish, weak.text.astype(str)], ignore_index=True)
    y = np.r_[np.zeros(len(gold_phish), dtype=int), np.ones(len(weak), dtype=int)]
    probe = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=10000)),
                      ("clf", LogisticRegression(class_weight="balanced", random_state=config["seed"], solver="liblinear"))])
    folds = StratifiedKFold(5, shuffle=True, random_state=config["seed"])
    prob = cross_val_predict(probe, x, y, cv=folds, method="predict_proba")[:, 1]
    auc = float(roc_auc_score(y, prob)); threshold = config["acceptance_criteria"]["source_probe_auc_warning"]
    shortcut = {"probe_scope": "training_only_derived_features", "probe_roc_auc": auc,
                "warning_threshold": threshold, "high_source_separability_warning": auc >= threshold,
                "probe_does_not_affect_classifier": True, "raw_features_reported": False}
    return {"coefficient_shift": shifts, "raw_tokens_included": False}, shortcut


def bootstrap_pair(left: dict, right: dict, iterations: int, seed: int) -> dict:
    y = np.asarray(left["y"]); lp = np.asarray(left["probability"]); rp = np.asarray(right["probability"])
    rng = np.random.default_rng(seed); requested = ["recall", "precision", "f1", "mcc", "pr_auc", "brier_score", "false_negatives", "false_positives"]
    samples = {name: [] for name in requested}
    def values(prob: np.ndarray, indices: np.ndarray) -> dict:
        return metrics(y[indices], prob[indices], .5)
    full_left = values(lp, np.arange(len(y))); full_right = values(rp, np.arange(len(y)))
    for _ in range(iterations):
        idx = rng.integers(0, len(y), len(y)); a = values(lp, idx); b = values(rp, idx)
        for name in requested:
            if a[name] is not None and b[name] is not None: samples[name].append(float(b[name] - a[name]))
    result = {}
    for name in requested:
        vals = samples[name]
        result[name] = {"point_delta_right_minus_left": (float(full_right[name] - full_left[name])
                        if full_right[name] is not None and full_left[name] is not None else None),
                        "ci95": [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))] if vals else None,
                        "valid_bootstrap_samples": len(vals)}
    return result


def acceptance(metrics_by: dict, shortcut: dict, config: dict) -> dict:
    base = metrics_by["baseline"]; policy = config["acceptance_criteria"]; decisions = {}
    for name in ("weak_035", "weak_050"):
        ext0, ext = base["external_evaluation"], metrics_by[name]["external_evaluation"]
        shift0, shift = base["template_shift_diagnostic"], metrics_by[name]["template_shift_diagnostic"]
        checks = {
            "external_recall": ext["recall"] >= ext0["recall"] - policy["external_recall_max_decrease"],
            "external_precision": ext["precision"] >= ext0["precision"] - policy["external_precision_max_decrease"],
            "external_fpr": (1-ext["specificity"]) <= (1-ext0["specificity"]) + policy["external_fpr_max_increase"],
            "external_brier": ext["brier_score"] <= ext0["brier_score"] + policy["external_brier_max_increase"],
            "template_shift_f1": shift["f1"] >= shift0["f1"] - policy["template_shift_f1_max_decrease"],
            "no_clear_source_artifact_dependence": not shortcut["high_source_separability_warning"],
        }
        decisions[name] = {"checks": checks, "eligible_for_recommendation": all(checks.values())}
    eligible = [name for name, item in decisions.items() if item["eligible_for_recommendation"]]
    if eligible:
        best = max(eligible, key=lambda item: metrics_by[item]["external_evaluation"]["f1"])
        recommendation = f"adopt_{best}_for_further_validation"
    elif any(not item["checks"]["no_clear_source_artifact_dependence"] and all(v for k, v in item["checks"].items() if k != "no_clear_source_artifact_dependence") for item in decisions.values()):
        recommendation = "inconclusive_collect_more_evidence"
    else:
        recommendation = "retain_baseline"
    return {"recommendation": recommendation, "activation_performed": False, "decisions": decisions,
            "policy": policy, "boundary_integrity_required": True}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False), encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False).stdout.strip()


def privacy_scan(report_dir: Path) -> dict:
    violations = []
    # Reports may be partitioned into per-experiment directories.  Scan
    # recursively so a nested artifact cannot accidentally leak message data.
    paths = [path for path in report_dir.rglob("*") if path.is_file()]
    for path in paths:
        if path.suffix.lower() not in {".json", ".md"}: continue
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_REPORT_PATTERNS:
            if pattern.search(text): violations.append({"file": path.name, "pattern": pattern.pattern})
    if violations: raise RuntimeError(f"Privacy scan failed: {violations}")
    return {"status": "passed", "files_scanned": len(paths), "violations": 0}


def run_suite(config_path: str | Path, experiments: list[str], verify_only: bool = False, force: bool = False) -> dict:
    config, root, config_file = load_config(config_path)
    audit, baseline, weak, evaluations = boundary_audit(config, root)
    artifact_root = root / config["paths"]["artifact_dir"]; report_dir = root / config["paths"]["report_dir"]
    active_before = sha256_file(root / config["paths"]["active_model"])
    if active_before != config["expected_sha256"]["active_model"]: raise RuntimeError("Active model changed before experiment")
    if verify_only:
        return {"boundary_audit": audit, "active_model_unchanged": True}
    if set(experiments) != set(EXPERIMENT_IDS):
        # Individual training is supported, but comparison reports require all artifacts.
        selected = experiments
    else: selected = list(EXPERIMENT_IDS)
    materialized = {}; training_summary = {}; metrics_by = {}; prediction_sets = {}; fn_by = {}; fp_by = {}; models = {}
    for experiment in selected:
        exp_dir = artifact_root / experiment
        completed = exp_dir / "metadata.json"
        if completed.exists() and not force: raise FileExistsError(f"Completed experiment exists: {experiment}; use --force-retrain")
        dataset, info = materialize(experiment, config, baseline, weak, exp_dir / "training_dataset.csv")
        materialized[experiment] = info
        all_metrics, predictions, fn, fp = train_and_evaluate(experiment, config, root, dataset, evaluations, exp_dir)
        bundle = joblib.load(exp_dir / "model.joblib"); models[experiment] = bundle["pipeline"]
        metrics_by[experiment] = all_metrics; prediction_sets[experiment] = predictions; fn_by[experiment] = fn; fp_by[experiment] = fp
        training_summary[experiment] = {**info, "label_counts": {str(k): int(v) for k, v in dataset.label.value_counts().items()},
            "label_quality_counts": {str(k): int(v) for k, v in dataset.label_quality.value_counts().items()},
            "feature_dimensions": len(models[experiment].named_steps["features"].get_feature_names_out()),
            "fixed_threshold": .5, "experimental_only": True, "deployment_allowed": False}
    if set(selected) != set(EXPERIMENT_IDS):
        return {"completed": selected, "comparison_generated": False, "boundary_audit": audit}
    if materialized["weak_035"]["non_weight_sha256"] != materialized["weak_050"]["non_weight_sha256"]:
        raise RuntimeError("B/C membership differs")
    if materialized["baseline"]["membership_sha256"] == materialized["weak_035"]["membership_sha256"]:
        raise RuntimeError("Baseline unexpectedly contains weak rows")
    feature_shift, shortcut = source_shortcut(models, baseline, weak, config)
    boot = {}
    pairs = [("baseline", "weak_035"), ("baseline", "weak_050"), ("weak_035", "weak_050")]
    for left, right in pairs:
        boot[f"{left}_vs_{right}"] = {}
        for index, eval_name in enumerate(evaluations):
            boot[f"{left}_vs_{right}"][eval_name] = bootstrap_pair(prediction_sets[left][eval_name], prediction_sets[right][eval_name],
                config["bootstrap_iterations"], config["bootstrap_seed"] + index)
    recommendation = acceptance(metrics_by, shortcut, config)
    reproducibility = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "platform": platform.platform(), "packages": {name: importlib.metadata.version(name) for name in ("numpy", "pandas", "scikit-learn", "joblib")},
        "git_commit": _git(root, "rev-parse", "HEAD"), "working_tree_dirty": bool(_git(root, "status", "--porcelain")),
        "config_sha256": sha256_file(config_file), "seeds": {"training": config["seed"], "bootstrap": config["bootstrap_seed"]}}
    manifest = {"suite": config["experiment_suite"], "experiments": config["experiments"], "fixed_threshold": .5,
        "experimental_only": True, "deployment_allowed": False, "reproducibility": reproducibility, "materialized": materialized,
        "active_model_sha256_before": active_before}
    confusion = {exp: {ev: {key: value for key, value in met.items() if key in {"true_positives","true_negatives","false_positives","false_negatives"}}
                       for ev, met in values.items()} for exp, values in metrics_by.items()}
    calibration = {exp: {ev: {key: met[key] for key in ("log_loss","brier_score","expected_calibration_error","mean_probability_by_class")}
                         for ev, met in values.items()} for exp, values in metrics_by.items()}
    _write_json(report_dir / "experiment_manifest.json", manifest); _write_json(report_dir / "dataset_boundary_audit.json", audit)
    _write_json(report_dir / "training_summary.json", training_summary); _write_json(report_dir / "metrics_by_experiment.json", metrics_by)
    _write_json(report_dir / "confusion_matrices.json", confusion); _write_json(report_dir / "calibration_summary.json", calibration)
    _write_json(report_dir / "false_negative_analysis.json", fn_by); _write_json(report_dir / "false_positive_analysis.json", fp_by)
    _write_json(report_dir / "feature_shift_analysis.json", feature_shift); _write_json(report_dir / "source_shortcut_analysis.json", shortcut)
    _write_json(report_dir / "bootstrap_comparison.json", boot); _write_json(report_dir / "final_recommendation.json", recommendation)
    table = ["# Fixed-threshold experiment comparison", "", "All models are experimental only; threshold = 0.50.", "",
             "| Evaluation | Experiment | Rows | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR | Brier | ECE |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for ev in evaluations:
        for exp in EXPERIMENT_IDS:
            m=metrics_by[exp][ev]; fpr=None if m["specificity"] is None else 1-m["specificity"]
            fmt=lambda v: "undefined" if v is None else f"{v:.4f}"
            table.append(f"| {ev} | {exp} | {m['rows']} | {fmt(m['accuracy'])} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['roc_auc'])} | {fmt(m['pr_auc'])} | {fmt(m['false_positive_rate'])} | {fmt(m['false_negative_rate'])} | {fmt(m['brier_score'])} | {fmt(m['expected_calibration_error'])} |")
    (report_dir / "metrics_comparison.md").write_text("\n".join(table)+"\n", encoding="utf-8")
    md = f"# Final recommendation\n\nRecommendation: `{recommendation['recommendation']}`.\n\nNo model was activated or deployed. High source separability warning: `{shortcut['high_source_separability_warning']}`.\n"
    (report_dir / "final_recommendation.md").write_text(md, encoding="utf-8")
    scan = privacy_scan(report_dir)
    active_after = sha256_file(root / config["paths"]["active_model"])
    if active_after != active_before: raise RuntimeError("Active model was modified")
    return {"training_summary": training_summary, "metrics": metrics_by, "recommendation": recommendation,
            "shortcut": shortcut, "boundary_audit": audit, "privacy_scan": scan, "active_model_unchanged": True,
            "report_dir": str(report_dir)}
