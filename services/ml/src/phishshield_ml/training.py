"""English-first candidate comparison, calibration, and artifact reporting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from scipy.special import expit
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from .config import MLConfig
from .dataset import prepare_dataset, split_dataset
from .evaluation import evaluate_predictions, evaluate_thresholds, write_metrics_json
from .schemas import Metrics, TrainingSummary


THRESHOLDS = [round(value, 3) for value in np.arange(0.20, 0.701, 0.025)]
MAX_RECOMMENDED_FPR = 0.12


def _word_vectorizer(config: MLConfig) -> TfidfVectorizer:
    return TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=config.min_df, max_df=config.max_df, max_features=config.max_features, sublinear_tf=True, strip_accents="unicode")


def _features(config: MLConfig, include_char: bool) -> FeatureUnion:
    transformers = [("word_tfidf", _word_vectorizer(config))]
    if include_char:
        transformers.append(("char_tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=config.max_features, sublinear_tf=True, strip_accents="unicode")))
    return FeatureUnion(transformers)


def build_candidates(config: MLConfig) -> dict[str, Pipeline]:
    logistic = lambda: LogisticRegression(class_weight="balanced", random_state=config.random_state, solver="liblinear", max_iter=config.max_iter)
    return {
        "A_word_tfidf_logistic_regression": Pipeline([("features", _features(config, False)), ("clf", logistic())]),
        "B_word_char_tfidf_logistic_regression": Pipeline([("features", _features(config, True)), ("clf", logistic())]),
        "C_word_char_tfidf_calibrated_linear_svc": Pipeline([
            ("features", _features(config, True)),
            ("clf", CalibratedClassifierCV(LinearSVC(class_weight="balanced", random_state=config.random_state), method="sigmoid", cv=5)),
        ]),
    }


def build_pipeline(config: MLConfig) -> Pipeline:
    """Compatibility helper returning candidate A."""
    return build_candidates(config)["A_word_tfidf_logistic_regression"]


def _probabilities(pipeline: Pipeline, texts: list[str]) -> list[float]:
    return pipeline.predict_proba(texts)[:, 1].astype(float).tolist()


def _raw_svc_probabilities(pipeline: Pipeline, texts: list[str]) -> list[float]:
    features = pipeline.named_steps["features"].transform(texts)
    classifier = pipeline.named_steps["clf"]
    scores = [calibrated.estimator.decision_function(features) for calibrated in classifier.calibrated_classifiers_]
    return expit(np.mean(np.vstack(scores), axis=0)).astype(float).tolist()


def _predictions(probabilities: list[float], threshold: float) -> list[int]:
    return [int(value >= threshold) for value in probabilities]


def _select_threshold(rows: list[dict]) -> dict:
    eligible = [row for row in rows if row["false_positive_rate"] <= MAX_RECOMMENDED_FPR]
    candidates = eligible or rows
    return min(candidates, key=lambda row: (row["false_negative_rate"], -row["f1"], row["false_positive_rate"], abs(row["threshold"] - 0.5)))


def _calibration_buckets(labels: list[int], probabilities: list[float]) -> list[dict]:
    fraction, mean = calibration_curve(labels, probabilities, n_bins=10, strategy="quantile")
    return [{"mean_predicted_probability": round(float(p), 6), "observed_phishing_rate": round(float(o), 6)} for p, o in zip(mean, fraction, strict=True)]


def _scenario_metrics(frame, probabilities: list[float], threshold: float) -> dict:
    rows = {}
    scenarios = frame.get("scenario")
    if scenarios is None:
        return rows
    for scenario in sorted(set(scenarios.astype(str))):
        mask = scenarios.astype(str).eq(scenario).tolist()
        labels = [int(label) for label, include in zip(frame["label"], mask, strict=True) if include]
        probs = [prob for prob, include in zip(probabilities, mask, strict=True) if include]
        rows[scenario] = {"rows": len(labels), **asdict(evaluate_predictions(labels, _predictions(probs, threshold), probs))}
    return rows


def _hashes(frame) -> list[str]:
    return sorted(hashlib.sha256(text.encode("utf-8")).hexdigest() for text in frame["text"])


def _write_error_analysis(path: Path, frame, probabilities: list[float], threshold: float) -> None:
    false_positives, false_negatives = [], []
    for index, (label, probability) in enumerate(zip(frame["label"], probabilities, strict=True)):
        if int(probability >= threshold) == int(label):
            continue
        row = {"id": f"test-{index + 1}", "probability": float(probability), "scenario": str(frame.iloc[index].get("scenario", "unknown")), "provenance": str(frame.iloc[index].get("provenance_type", "unknown")), "length": len(frame.iloc[index]["text"])}
        (false_positives if int(label) == 0 else false_negatives).append(row)
    lines = ["# Error Analysis", "", "No subjects, addresses, URLs, or complete message bodies are included.", "", f"## False positives ({len(false_positives)})", ""]
    lines += [f"- {row['id']}: p={row['probability']:.3f}, scenario={row['scenario']}, provenance={row['provenance']}, characters={row['length']}." for row in false_positives[:12]] or ["- None in the frozen internal test split."]
    lines += ["", f"## False negatives ({len(false_negatives)})", ""]
    lines += [f"- {row['id']}: p={row['probability']:.3f}, scenario={row['scenario']}, provenance={row['provenance']}, characters={row['length']}." for row in false_negatives[:12]] or ["- None in the frozen internal test split."]
    lines += ["", "## Patterns and limitations", "", "- Legitimate account, security, invoice, support, and password messages overlap lexically with phishing.", "- Synthetic templates can be easier to separate than naturally occurring mail and must not dominate confidence claims.", "- Source formatting and template families can create shortcuts despite grouped splitting.", "- The external benchmark is small after exact deduplication and is not representative of production mail.", "- Text classification cannot replace header authentication, rendered-link, attachment, or sender-domain evidence.", "- This is an academic baseline, not production-grade protection.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def train_model(dataset_path: str | Path, model_output: str | Path, metrics_output: str | Path, config: MLConfig | None = None, external_dataset_path: str | Path | None = None) -> TrainingSummary:
    cfg = config or MLConfig(model_output=Path(model_output), metrics_output=Path(metrics_output))
    prepared = prepare_dataset(dataset_path)
    train_frame, valid_frame, test_frame, split_summary = split_dataset(prepared.dataframe, random_state=cfg.random_state)
    train_texts, train_labels = train_frame["text"].tolist(), train_frame["label"].tolist()
    valid_texts, valid_labels = valid_frame["text"].tolist(), valid_frame["label"].tolist()

    candidate_rows, fitted = [], {}
    calibration_comparison = {}
    for name, pipeline in build_candidates(cfg).items():
        pipeline.fit(train_texts, train_labels)
        fitted[name] = pipeline
        probabilities = _probabilities(pipeline, valid_texts)
        threshold_rows = evaluate_thresholds(valid_labels, probabilities, THRESHOLDS)
        selected = _select_threshold(threshold_rows)
        metrics = evaluate_predictions(valid_labels, _predictions(probabilities, float(selected["threshold"])), probabilities)
        candidate_rows.append({"candidate": name, "selected_validation_threshold": float(selected["threshold"]), **asdict(metrics)})
        if name.startswith("C_"):
            raw = _raw_svc_probabilities(pipeline, valid_texts)
            calibration_comparison[name] = {
                "method": "five-fold sigmoid calibration on training only",
                "raw_sigmoid_brier_score": evaluate_predictions(valid_labels, _predictions(raw, 0.5), raw).brier_score,
                "calibrated_brier_score": metrics.brier_score,
                "raw_buckets": _calibration_buckets(valid_labels, raw),
                "calibrated_buckets": _calibration_buckets(valid_labels, probabilities),
            }

    eligible = [row for row in candidate_rows if row["false_positive_rate"] <= MAX_RECOMMENDED_FPR]
    selected_row = max(eligible or candidate_rows, key=lambda row: (row["recall"], row["pr_auc"] or 0.0, row["f1"], -row["false_positive_rate"]))
    selected_name = selected_row["candidate"]
    selected_threshold = float(selected_row["selected_validation_threshold"])
    pipeline = fitted[selected_name]
    valid_proba = _probabilities(pipeline, valid_texts)
    validation_metrics = evaluate_predictions(valid_labels, _predictions(valid_proba, selected_threshold), valid_proba)

    # The grouped internal holdout is a development diagnostic. The separately supplied
    # external benchmark is the final untouched evaluation set.
    test_labels, test_texts = test_frame["label"].tolist(), test_frame["text"].tolist()
    test_proba = _probabilities(pipeline, test_texts)
    test_metrics = evaluate_predictions(test_labels, _predictions(test_proba, selected_threshold), test_proba)
    external_payload = None
    if external_dataset_path:
        external = prepare_dataset(external_dataset_path).dataframe
        external_labels, external_texts = external["label"].tolist(), external["text"].tolist()
        external_proba = _probabilities(pipeline, external_texts)
        external_payload = {"rows": len(external), "metrics": asdict(evaluate_predictions(external_labels, _predictions(external_proba, selected_threshold), external_proba)), "calibration_buckets": _calibration_buckets(external_labels, external_proba), "used_for_selection": False}

    generated_at = datetime.now(timezone.utc).isoformat()
    reports_dir = Path(metrics_output).parent
    reports_dir.mkdir(parents=True, exist_ok=True)
    source_audit_path = reports_dir / "corpus_audit.json"
    source_audit = json.loads(source_audit_path.read_text(encoding="utf-8")) if source_audit_path.exists() else None
    if external_payload and source_audit and source_audit.get("final_external_benchmark"):
        source_audit["final_external_benchmark"]["evaluation_status"] = "evaluated once after final model and threshold lock"
        source_audit_path.write_text(json.dumps(source_audit, indent=2, sort_keys=True), encoding="utf-8")
    feature_config = {"candidate": selected_name, "word_tfidf": {"ngram_range": [1, 2], "max_features": cfg.max_features, "sublinear_tf": True}, "char_tfidf": {"enabled": "word_char" in selected_name, "analyzer": "char_wb", "ngram_range": [3, 5], "max_features": cfg.max_features}, "class_weight": "balanced", "random_state": cfg.random_state, "calibration": "five-fold sigmoid on training" if selected_name.startswith("C_") else "native logistic probability"}
    evaluation_metrics = {"validation_selected_threshold": asdict(validation_metrics), "test_selected_threshold": asdict(test_metrics), "external_benchmark": external_payload}
    bundle = {"pipeline": pipeline, "model_version": cfg.model_version, "label_mapping": {"legitimate": 0, "phishing": 1}, "preprocessing_version": cfg.preprocessing_version, "feature_config": feature_config, "decision_threshold": selected_threshold, "training_timestamp": generated_at, "training_dataset_summary": asdict(prepared.summary), "dataset_provenance": source_audit, "evaluation_metrics": evaluation_metrics}
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)

    threshold_rows = evaluate_thresholds(valid_labels, valid_proba, THRESHOLDS)
    metrics_payload = {"model_version": cfg.model_version, "generated_at": generated_at, "positive_class": "phishing", "selected_candidate": selected_name, "selected_threshold": selected_threshold, "selection_data": "validation only", "internal_grouped_holdout_evaluations_this_run": 1, "dataset_summary": asdict(prepared.summary), "split_summary": asdict(split_summary), "candidate_validation_comparison": candidate_rows, "validation_selected_threshold": asdict(validation_metrics), "internal_grouped_holdout": asdict(test_metrics), "internal_scenario_metrics": _scenario_metrics(test_frame, test_proba, selected_threshold), "final_external_benchmark": external_payload}
    write_metrics_json(metrics_payload, metrics_output)
    write_metrics_json({"selection_policy": {"data": "validation only", "objective": "minimize false negatives subject to FPR <= 0.12, then PR-AUC/F1", "selected_candidate": selected_name, "selected_threshold": selected_threshold}, "validation_thresholds": threshold_rows}, reports_dir / "threshold_analysis.json")
    write_metrics_json({"selected_candidate": selected_name, "validation": calibration_comparison, "selected_validation_buckets": _calibration_buckets(valid_labels, valid_proba), "selected_test_buckets": _calibration_buckets(test_labels, test_proba), "external": external_payload["calibration_buckets"] if external_payload else None}, reports_dir / "calibration_analysis.json")
    write_metrics_json({"model_version": cfg.model_version, "training_timestamp": generated_at, "artifact_path": str(model_path), "artifact_size_bytes": model_path.stat().st_size, "decision_threshold": selected_threshold, "feature_config": feature_config, "dataset_summary": asdict(prepared.summary), "split_summary": asdict(split_summary), "evaluation_policy": "candidate and threshold selection use validation only; grouped internal holdout is diagnostic; separately supplied external benchmark is final"}, reports_dir / "metadata.json")
    write_metrics_json({"random_state": cfg.random_state, "strategy": "StratifiedGroupKFold; template groups are disjoint", "train_sha256": _hashes(train_frame), "validation_sha256": _hashes(valid_frame), "test_sha256": _hashes(test_frame)}, reports_dir / "split_manifest.json")
    _write_error_analysis(reports_dir / "error_analysis.md", test_frame, test_proba, selected_threshold)
    summary_lines = ["# English-First Training Summary", "", f"Generated: {generated_at}", f"Model: `{cfg.model_version}`", f"Selected candidate: `{selected_name}`", f"Selected threshold: `{selected_threshold:.3f}` (validation only)", f"Artifact: `{model_path.as_posix()}` ({model_path.stat().st_size:,} bytes)", "", "## Corpus", "", f"- Core rows: {prepared.summary.total_rows} (legitimate={prepared.summary.legitimate_count}, phishing={prepared.summary.phishing_count})", f"- English estimate: {prepared.summary.english_percentage:.2f}% ({prepared.summary.english_count}/{prepared.summary.total_rows}); 80% gate passed.", f"- Grouped split: train={split_summary.train_rows}, validation={split_summary.validation_rows}, internal diagnostic={split_summary.test_rows}.", "", "## Internal grouped diagnostic", "", f"- Accuracy={test_metrics.accuracy:.4f}; precision={test_metrics.precision:.4f}; recall={test_metrics.recall:.4f}; F1={test_metrics.f1:.4f}; ROC-AUC={test_metrics.roc_auc:.4f}; PR-AUC={test_metrics.pr_auc:.4f}.", f"- Confusion matrix={test_metrics.confusion_matrix}; FPR={test_metrics.false_positive_rate:.4f}; FNR={test_metrics.false_negative_rate:.4f}; Brier={test_metrics.brier_score:.4f}.", "", "The model is an academic baseline. Synthetic coverage, small external data, and text-only inference prevent production-grade accuracy claims.", ""]
    (reports_dir / "training_summary.md").write_text("\n".join(summary_lines), encoding="utf-8")
    return TrainingSummary(model_version=cfg.model_version, preprocessing_version=cfg.preprocessing_version, dataset_summary=prepared.summary, split_summary=split_summary, validation_metrics=validation_metrics, test_metrics=test_metrics, selected_threshold=selected_threshold, model_path=str(model_path), metadata_path=str(reports_dir / "metadata.json"))
