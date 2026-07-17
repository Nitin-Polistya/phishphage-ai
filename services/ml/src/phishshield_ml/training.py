"""Training and reporting entrypoints for the PhishPhage ML baseline."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .config import MLConfig
from .dataset import prepare_dataset, split_dataset
from .evaluation import evaluate_predictions, evaluate_thresholds, write_metrics_json
from .schemas import Metrics, TrainingSummary


THRESHOLDS = [round(value / 100, 2) for value in range(10, 91, 5)]
MAX_RECOMMENDED_FPR = 0.10


def build_pipeline(config: MLConfig) -> Pipeline:
    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                min_df=config.min_df,
                max_df=config.max_df,
                max_features=config.max_features,
                sublinear_tf=True,
                strip_accents="unicode",
            ),
        ),
        (
            "clf",
            LogisticRegression(
                class_weight="balanced",
                random_state=config.random_state,
                solver="liblinear",
                max_iter=config.max_iter,
            ),
        ),
    ])


def _positive_class_probability(pipeline: Pipeline, texts: list[str]) -> list[float]:
    return pipeline.predict_proba(texts)[:, 1].tolist()


def _predictions_at_threshold(probabilities: list[float], threshold: float) -> list[int]:
    return [1 if probability >= threshold else 0 for probability in probabilities]


def _select_threshold(rows: list[dict]) -> dict:
    eligible = [row for row in rows if row["false_positive_rate"] <= MAX_RECOMMENDED_FPR]
    candidates = eligible or rows
    return min(
        candidates,
        key=lambda row: (
            row["false_negative_rate"],
            -row["f1"],
            row["false_positive_rate"],
            abs(row["threshold"] - 0.5),
        ),
    )


def _safe_error_rows(labels: list[int], probabilities: list[float], texts: list[str], threshold: float) -> tuple[list[dict], list[dict]]:
    themes = {
        "credentials": ("password", "login", "credential", "verify"),
        "urgency": ("urgent", "immediately", "suspend", "expire"),
        "financial": ("invoice", "payment", "bank", "refund"),
        "delivery": ("delivery", "parcel", "shipment", "courier"),
        "links": ("http://", "https://", "click"),
    }
    false_positives: list[dict] = []
    false_negatives: list[dict] = []
    for index, (label, probability, text) in enumerate(zip(labels, probabilities, texts, strict=True)):
        predicted = int(probability >= threshold)
        if predicted == label:
            continue
        lowered = text.lower()
        row = {
            "example_id": f"test-{index + 1}",
            "true_label": "phishing" if label else "legitimate",
            "phishing_probability": round(float(probability), 6),
            "character_count": len(text),
            "themes": [name for name, terms in themes.items() if any(term in lowered for term in terms)] or ["other"],
        }
        (false_positives if label == 0 else false_negatives).append(row)
    return false_positives, false_negatives


def _write_error_analysis(path: Path, false_positives: list[dict], false_negatives: list[dict]) -> None:
    def lines_for(rows: list[dict]) -> list[str]:
        if not rows:
            return ["- No examples at the selected threshold in this test split."]
        return [
            f"- {row['example_id']}: probability={row['phishing_probability']:.3f}, "
            f"length={row['character_count']}, themes={', '.join(row['themes'])}."
            for row in rows[:10]
        ]

    content = [
        "# Error Analysis",
        "",
        "This report intentionally excludes subjects, senders, URLs, and raw email bodies.",
        "",
        f"## False positives ({len(false_positives)})",
        "",
        *lines_for(false_positives),
        "",
        f"## False negatives ({len(false_negatives)})",
        "",
        *lines_for(false_negatives),
        "",
        "## Common patterns and limitations",
        "",
        "- Errors can reflect lexical overlap: legitimate security/support messages and phishing messages often share account vocabulary.",
        "- Synthetic templates can make urgency, credential, invoice, and delivery wording unrealistically separable.",
        "- The model sees text only; it does not inspect sender reputation, authentication results, rendered HTML, attachment content, or URL destinations.",
        "- The training mix combines a real Spanish corpus with a small, highly duplicated English synthetic/validation corpus; language and source artifacts may dominate predictions.",
        "- Metrics from this corpus are an academic baseline and must not be treated as production-grade accuracy.",
        "",
    ]
    path.write_text("\n".join(content), encoding="utf-8")


def _metrics_line(name: str, metrics: Metrics) -> str:
    return (
        f"- {name}: accuracy={metrics.accuracy:.4f}, precision={metrics.precision:.4f}, "
        f"recall={metrics.recall:.4f}, F1={metrics.f1:.4f}, ROC-AUC={metrics.roc_auc:.4f}, "
        f"FPR={metrics.false_positive_rate:.4f}, FNR={metrics.false_negative_rate:.4f}, "
        f"confusion_matrix={metrics.confusion_matrix}"
    )


def train_model(dataset_path: str | Path, model_output: str | Path, metrics_output: str | Path, config: MLConfig | None = None) -> TrainingSummary:
    cfg = config or MLConfig(model_output=Path(model_output), metrics_output=Path(metrics_output))
    prepared = prepare_dataset(dataset_path)
    reports_dir = Path(metrics_output).parent
    source_summary_path = reports_dir / "dataset_summary.json"
    source_preparation = json.loads(source_summary_path.read_text(encoding="utf-8")) if source_summary_path.exists() else None
    train_frame, valid_frame, test_frame, split_summary = split_dataset(prepared.dataframe, random_state=cfg.random_state)

    pipeline = build_pipeline(cfg)
    pipeline.fit(train_frame["text"].tolist(), train_frame["label"].tolist())

    valid_labels = valid_frame["label"].tolist()
    valid_proba = _positive_class_probability(pipeline, valid_frame["text"].tolist())
    threshold_rows = evaluate_thresholds(valid_labels, valid_proba, THRESHOLDS)
    selected = _select_threshold(threshold_rows)
    selected_threshold = float(selected["threshold"])

    train_labels = train_frame["label"].tolist()
    train_proba = _positive_class_probability(pipeline, train_frame["text"].tolist())
    test_labels = test_frame["label"].tolist()
    test_texts = test_frame["text"].tolist()
    test_proba = _positive_class_probability(pipeline, test_texts)
    train_metrics = evaluate_predictions(train_labels, _predictions_at_threshold(train_proba, selected_threshold), train_proba)
    validation_metrics = evaluate_predictions(valid_labels, _predictions_at_threshold(valid_proba, selected_threshold), valid_proba)
    test_metrics = evaluate_predictions(test_labels, _predictions_at_threshold(test_proba, selected_threshold), test_proba)
    baseline_test_metrics = evaluate_predictions(test_labels, _predictions_at_threshold(test_proba, 0.5), test_proba)

    generated_at = datetime.now(timezone.utc).isoformat()
    feature_config = {
        "lowercase": True,
        "ngram_range": [1, 2],
        "min_df": cfg.min_df,
        "max_df": cfg.max_df,
        "max_features": cfg.max_features,
        "sublinear_tf": True,
        "strip_accents": "unicode",
        "solver": "liblinear",
        "class_weight": "balanced",
        "random_state": cfg.random_state,
        "max_iter": cfg.max_iter,
    }
    evaluation_metrics = {
        "train_selected_threshold": asdict(train_metrics),
        "validation_selected_threshold": asdict(validation_metrics),
        "test_selected_threshold": asdict(test_metrics),
        "test_default_threshold_0_5": asdict(baseline_test_metrics),
    }
    bundle = {
        "pipeline": pipeline,
        "model_version": cfg.model_version,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "preprocessing_version": cfg.preprocessing_version,
        "feature_config": feature_config,
        "decision_threshold": selected_threshold,
        "training_timestamp": generated_at,
        "training_dataset_summary": asdict(prepared.summary),
        "dataset_provenance": source_preparation,
        "evaluation_metrics": evaluation_metrics,
    }
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)

    reports_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = reports_dir / "metadata.json"
    threshold_path = reports_dir / "threshold_analysis.json"
    error_path = reports_dir / "error_analysis.md"
    summary_path = reports_dir / "training_summary.md"

    metrics_payload = {
        "model_version": cfg.model_version,
        "generated_at": generated_at,
        "positive_class": "phishing",
        "selected_threshold": selected_threshold,
        "dataset_summary": asdict(prepared.summary),
        "source_preparation": source_preparation,
        "split_summary": asdict(split_summary),
        **evaluation_metrics,
    }
    write_metrics_json(metrics_payload, metrics_output)
    write_metrics_json({
        "model_version": cfg.model_version,
        "generated_at": generated_at,
        "selection_policy": {
            "objective": "minimize validation false-negative rate, then maximize F1",
            "maximum_preferred_false_positive_rate": MAX_RECOMMENDED_FPR,
            "selected_threshold": selected_threshold,
        },
        "validation_thresholds": threshold_rows,
    }, threshold_path)
    write_metrics_json({
        "model_version": cfg.model_version,
        "preprocessing_version": cfg.preprocessing_version,
        "training_timestamp": generated_at,
        "label_mapping": bundle["label_mapping"],
        "decision_threshold": selected_threshold,
        "feature_config": feature_config,
        "dataset_summary": asdict(prepared.summary),
        "dataset_provenance": source_preparation,
        "split_summary": asdict(split_summary),
        "artifact_path": str(model_path),
    }, metadata_path)

    false_positives, false_negatives = _safe_error_rows(test_labels, test_proba, test_texts, selected_threshold)
    _write_error_analysis(error_path, false_positives, false_negatives)
    summary_path.write_text("\n".join([
        "# Training Summary",
        "",
        f"Generated: {generated_at}",
        f"Model: `{cfg.model_version}`",
        f"Artifact: `{model_path.as_posix()}`",
        f"Selected phishing threshold: `{selected_threshold:.2f}`",
        "",
        "## Dataset and split",
        "",
        f"- Clean rows: {prepared.summary.total_rows} (legitimate={prepared.summary.legitimate_count}, phishing={prepared.summary.phishing_count})",
        f"- Removed: empty={prepared.summary.empty_rows_removed}, exact duplicates={prepared.summary.duplicate_rows_removed}",
        f"- Split: train={split_summary.train_rows}, validation={split_summary.validation_rows}, test={split_summary.test_rows}",
        "",
        "## Metrics",
        "",
        _metrics_line("Train", train_metrics),
        _metrics_line("Validation", validation_metrics),
        _metrics_line("Test", test_metrics),
        "",
        "Academic baseline only; these results do not establish production-grade phishing protection.",
        "",
    ]), encoding="utf-8")

    return TrainingSummary(
        model_version=cfg.model_version,
        preprocessing_version=cfg.preprocessing_version,
        dataset_summary=prepared.summary,
        split_summary=split_summary,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        selected_threshold=selected_threshold,
        model_path=str(model_path),
        metadata_path=str(metadata_path),
    )
