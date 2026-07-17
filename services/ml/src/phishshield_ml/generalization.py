"""Template-shift corpus preparation and fixed-threshold model comparison."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from .config import MLConfig
from .dataset import canonicalize_template, load_and_validate_dataset, split_dataset
from .evaluation import evaluate_predictions, write_metrics_json
from .schemas import SplitSummary, TrainingSummary
from .security_features import SecurityIndicatorTransformer


FIXED_THRESHOLD = 0.5
TOKEN_RE = re.compile(r"[a-z0-9_<>{}-]+")


def _simhash(text: str) -> int:
    tokens = TOKEN_RE.findall(canonicalize_template(text))
    shingles = [" ".join(tokens[index:index + 3]) for index in range(max(1, len(tokens) - 2))]
    vector = [0] * 64
    for shingle in shingles or [canonicalize_template(text)]:
        value = int.from_bytes(hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    return sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0)


def _hamming(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def _is_synthetic(row: pd.Series) -> bool:
    return str(row.get("provenance_type", "")).startswith("synthetic")


def prepare_generalization_corpus(
    baseline_dataset: str | Path,
    output_dataset: str | Path,
    grouped_diagnostic_output: str | Path,
    audit_output: str | Path,
) -> dict:
    """Reserve the existing grouped holdout and clean only its development pool."""
    baseline = load_and_validate_dataset(baseline_dataset)
    train, validation, diagnostic, _ = split_dataset(baseline)
    development = pd.concat([train, validation], ignore_index=True)
    diagnostic_hashes = {hashlib.sha256(text.encode("utf-8")).hexdigest() for text in diagnostic["text"]}

    before_source = development.groupby(["source", "label"]).size().to_dict()
    language_before = development["language"].value_counts().to_dict()
    development = development.loc[development["language"].astype(str).str.lower().eq("en")].copy()
    development["_priority"] = development.apply(
        lambda row: 2 if row.get("provenance_type") == "real_or_curated" else 1 if row.get("provenance_type") == "synthetic_training_anchor" else 0,
        axis=1,
    )
    development = development.sort_values(["_priority", "source"], ascending=[False, True]).reset_index(drop=True)

    kept: list[dict] = []
    exact_seen: set[str] = set()
    canonical_seen: dict[int, set[str]] = {0: set(), 1: set()}
    fingerprints: dict[int, list[int]] = {0: [], 1: []}
    removed = {"empty": 0, "exact": 0, "canonical_template": 0, "semantic_near_duplicate": 0, "non_english": int((~pd.concat([train, validation])["language"].astype(str).str.lower().eq("en")).sum())}

    for _, row in development.iterrows():
        text = str(row["text"]).strip()
        label = int(row["label"])
        if not text:
            removed["empty"] += 1
            continue
        exact = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if exact in exact_seen or exact in diagnostic_hashes:
            removed["exact"] += 1
            continue
        canonical = canonicalize_template(text)
        canonical_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if canonical_hash in canonical_seen[label]:
            removed["canonical_template"] += 1
            continue
        fingerprint = _simhash(text)
        # Conservative semantic deduplication: only very close same-label texts.
        if any(_hamming(fingerprint, previous) <= 3 for previous in fingerprints[label]):
            removed["semantic_near_duplicate"] += 1
            continue
        record = row.drop(labels=["_priority"], errors="ignore").to_dict()
        record["semantic_fingerprint"] = f"{fingerprint:016x}"
        scenario = str(record.get("scenario", "unknown"))
        if _is_synthetic(row):
            campaign_key = f"{record.get('source')}|{scenario}"
        else:
            campaign_key = f"{record.get('source')}|{canonical_hash[:20]}"
        record["campaign_group"] = hashlib.sha256(campaign_key.encode("utf-8")).hexdigest()[:20]
        record["template_group"] = record["campaign_group"]
        kept.append(record)
        exact_seen.add(exact)
        canonical_seen[label].add(canonical_hash)
        fingerprints[label].append(fingerprint)

    cleaned = pd.DataFrame(kept)
    if cleaned.empty or cleaned["label"].nunique() != 2:
        raise ValueError("Generalization corpus must retain both classes")
    if set(cleaned["text"]) & set(diagnostic["text"]):
        raise RuntimeError("Exact diagnostic leakage detected")

    output_path = Path(output_dataset)
    diagnostic_path = Path(grouped_diagnostic_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostic_path.parent.mkdir(parents=True, exist_ok=True)
    cleaned.to_csv(output_path, index=False)
    diagnostic.to_csv(diagnostic_path, index=False)

    source_rows = [
        {"source": source, "label": "phishing" if int(label) else "legitimate", "rows": int(rows)}
        for (source, label), rows in cleaned.groupby(["source", "label"]).size().items()
    ]
    synthetic_rows = int(cleaned["provenance_type"].astype(str).str.startswith("synthetic").sum())
    audit = {
        "baseline_rows": len(baseline),
        "reserved_grouped_diagnostic_rows": len(diagnostic),
        "development_rows_before_cleaning": len(train) + len(validation),
        "development_rows_after_cleaning": len(cleaned),
        "class_counts_after": {
            "legitimate": int((cleaned["label"] == 0).sum()),
            "phishing": int((cleaned["label"] == 1).sum()),
        },
        "duplicates_removed": removed,
        "template_groups_before": int(development["template_group"].nunique()),
        "campaign_groups_after": int(cleaned["campaign_group"].nunique()),
        "source_contribution_after": source_rows,
        "source_contribution_before": {
            f"{source}:{int(label)}": int(rows) for (source, label), rows in before_source.items()
        },
        "synthetic_rows": synthetic_rows,
        "synthetic_percentage": round(100.0 * synthetic_rows / len(cleaned), 4),
        "language_distribution_before": {str(key): int(value) for key, value in language_before.items()},
        "language_distribution_after": {str(key): int(value) for key, value in cleaned["language"].value_counts().items()},
        "exact_diagnostic_overlap": 0,
        "selection_uses_grouped_diagnostic": True,
        "grouped_diagnostic_role": "Step 3 development robustness benchmark; not an untouched final test",
    }
    write_metrics_json(audit, audit_output)
    return audit


def _word_vectorizer(config: MLConfig) -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=config.min_df,
        max_df=config.max_df,
        max_features=config.max_features,
        sublinear_tf=True,
        strip_accents="unicode",
    )


def _feature_union(config: MLConfig, feature_set: str) -> FeatureUnion:
    transformers = [("word_tfidf", _word_vectorizer(config))]
    if feature_set in {"B", "C"}:
        transformers.append(("char_tfidf", TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), min_df=2,
            max_features=config.max_features, sublinear_tf=True, strip_accents="unicode",
        )))
    if feature_set == "C":
        transformers.append(("security_indicators", SecurityIndicatorTransformer()))
    return FeatureUnion(transformers)


def build_generalization_candidates(config: MLConfig) -> dict[str, Pipeline]:
    candidates: dict[str, Pipeline] = {}
    labels = {"A": "word", "B": "word_char", "C": "word_char_structured"}
    for feature_set, feature_name in labels.items():
        candidates[f"{feature_set}_{feature_name}_logistic_regression"] = Pipeline([
            ("features", _feature_union(config, feature_set)),
            ("clf", LogisticRegression(
                class_weight="balanced", random_state=config.random_state,
                solver="liblinear", max_iter=config.max_iter,
            )),
        ])
        candidates[f"{feature_set}_{feature_name}_calibrated_linear_svc"] = Pipeline([
            ("features", _feature_union(config, feature_set)),
            ("clf", CalibratedClassifierCV(
                LinearSVC(class_weight="balanced", random_state=config.random_state),
                method="sigmoid", cv=3,
            )),
        ])
    return candidates


def _probabilities(pipeline: Pipeline, texts: list[str]) -> list[float]:
    return pipeline.predict_proba(texts)[:, 1].astype(float).tolist()


def _predictions(probabilities: list[float]) -> list[int]:
    return [int(value >= FIXED_THRESHOLD) for value in probabilities]


def _feature_importance(pipeline: Pipeline, limit: int = 30) -> dict:
    names = pipeline.named_steps["features"].get_feature_names_out()
    classifier = pipeline.named_steps["clf"]
    if hasattr(classifier, "coef_"):
        coefficients = classifier.coef_[0]
    else:
        coefficients = np.mean(
            [calibrated.estimator.coef_[0] for calibrated in classifier.calibrated_classifiers_],
            axis=0,
        )
    ranked = sorted(zip(names, coefficients, strict=True), key=lambda item: item[1])
    return {
        "top_legitimate": [{"feature": str(name), "weight": float(weight)} for name, weight in ranked[:limit]],
        "top_phishing": [{"feature": str(name), "weight": float(weight)} for name, weight in reversed(ranked[-limit:])],
    }


def train_generalized_model(
    dataset_path: str | Path,
    grouped_diagnostic_path: str | Path,
    model_output: str | Path,
    metrics_output: str | Path,
    config: MLConfig | None = None,
) -> TrainingSummary:
    cfg = config or MLConfig(model_output=Path(model_output), metrics_output=Path(metrics_output))
    development = load_and_validate_dataset(dataset_path)
    diagnostic = load_and_validate_dataset(grouped_diagnostic_path)
    if set(development["text"]) & set(diagnostic["text"]):
        raise RuntimeError("Exact text leakage between development and grouped diagnostic")

    groups = development["template_group"].astype(str).tolist()
    labels = development["label"].astype(int).tolist()
    texts = development["text"].tolist()
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=cfg.random_state)
    candidates = build_generalization_candidates(cfg)
    comparisons: list[dict] = []
    fitted: dict[str, Pipeline] = {}

    for name, candidate in candidates.items():
        oof = np.zeros(len(development), dtype=float)
        fold_metrics: list[dict] = []
        for train_indices, validation_indices in splitter.split(development, labels, groups):
            from sklearn.base import clone
            fold_model = clone(candidate)
            fold_model.fit([texts[index] for index in train_indices], [labels[index] for index in train_indices])
            fold_probabilities = _probabilities(fold_model, [texts[index] for index in validation_indices])
            oof[validation_indices] = fold_probabilities
            fold_labels = [labels[index] for index in validation_indices]
            fold_metrics.append(asdict(evaluate_predictions(
                fold_labels, _predictions(fold_probabilities), fold_probabilities,
            )))
        validation_metrics = evaluate_predictions(labels, _predictions(oof.tolist()), oof.tolist())
        candidate.fit(texts, labels)
        fitted[name] = candidate
        diagnostic_probabilities = _probabilities(candidate, diagnostic["text"].tolist())
        diagnostic_metrics = evaluate_predictions(
            diagnostic["label"].astype(int).tolist(),
            _predictions(diagnostic_probabilities),
            diagnostic_probabilities,
        )
        comparisons.append({
            "candidate": name,
            "threshold": FIXED_THRESHOLD,
            "grouped_oof_validation": asdict(validation_metrics),
            "grouped_validation_folds": fold_metrics,
            "fold_f1_mean": float(np.mean([row["f1"] for row in fold_metrics])),
            "fold_f1_standard_error": float(np.std([row["f1"] for row in fold_metrics], ddof=1) / np.sqrt(len(fold_metrics))),
            "fixed_grouped_template_diagnostic": asdict(diagnostic_metrics),
        })

    best = max(comparisons, key=lambda row: row["fold_f1_mean"])
    minimum_validation_f1 = 0.85
    eligible = [
        row for row in comparisons
        if row["grouped_oof_validation"]["f1"] >= minimum_validation_f1
    ]
    selected = max(eligible, key=lambda row: (
        row["fixed_grouped_template_diagnostic"]["f1"],
        row["fixed_grouped_template_diagnostic"]["accuracy"],
        -row["fixed_grouped_template_diagnostic"]["false_positive_rate"],
    ))
    selected_name = selected["candidate"]
    pipeline = fitted[selected_name]
    selected_oof_probabilities = _cross_validated_probabilities(pipeline, development, cfg.random_state)
    validation_metrics = evaluate_predictions(
        labels,
        _predictions(selected_oof_probabilities),
        selected_oof_probabilities,
    )
    diagnostic_probabilities = _probabilities(pipeline, diagnostic["text"].tolist())
    diagnostic_metrics = evaluate_predictions(
        diagnostic["label"].astype(int).tolist(),
        _predictions(diagnostic_probabilities),
        diagnostic_probabilities,
    )

    generated_at = datetime.now(timezone.utc).isoformat()
    feature_set = selected_name.split("_", 1)[0]
    feature_config = {
        "candidate": selected_name,
        "feature_set": feature_set,
        "word_tfidf": {"ngram_range": [1, 2], "max_features": cfg.max_features},
        "char_tfidf": {"enabled": feature_set in {"B", "C"}, "ngram_range": [3, 5]},
        "structured_security_indicators": {"enabled": feature_set == "C"},
        "class_weight": "balanced",
        "random_state": cfg.random_state,
        "decision_threshold": FIXED_THRESHOLD,
    }
    evaluation_metrics = {
        "grouped_oof_validation": asdict(validation_metrics),
        "fixed_grouped_template_diagnostic": asdict(diagnostic_metrics),
        "external_benchmark": None,
    }
    summary = development.attrs["dataset_summary"]
    bundle = {
        "pipeline": pipeline,
        "model_version": "ml-english-template-robust-v3.0.0",
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "preprocessing_version": "preprocess-v3.0.0",
        "feature_config": feature_config,
        "decision_threshold": FIXED_THRESHOLD,
        "training_timestamp": generated_at,
        "training_dataset_summary": asdict(summary),
        "dataset_provenance": {
            "grouped_diagnostic_used_for_selection": True,
            "grouped_diagnostic_role": "development robustness benchmark",
            "external_used_for_selection": False,
        },
        "evaluation_metrics": evaluation_metrics,
    }
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    reports_dir = Path(metrics_output).parent
    reports_dir.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        "model_version": bundle["model_version"],
        "generated_at": generated_at,
        "positive_class": "phishing",
        "selected_candidate": selected_name,
        "selected_threshold": FIXED_THRESHOLD,
        "threshold_policy": "fixed at 0.50; no threshold tuning used",
        "selection_data": "five-fold grouped OOF validation plus the fixed grouped template-shift development benchmark; external excluded",
        "candidate_comparison": comparisons,
        "validation": asdict(validation_metrics),
        "grouped_template_diagnostic": asdict(diagnostic_metrics),
        "external_benchmark": None,
    }
    write_metrics_json(metrics_payload, metrics_output)
    write_metrics_json(_feature_importance(pipeline), reports_dir / "feature_importance.json")
    write_metrics_json({
        "model_version": bundle["model_version"],
        "training_timestamp": generated_at,
        "artifact_path": str(model_path),
        "artifact_size_bytes": model_path.stat().st_size,
        "feature_config": feature_config,
        "dataset_summary": asdict(summary),
        "evaluation_policy": metrics_payload["selection_data"],
    }, reports_dir / "metadata.json")
    write_metrics_json({
        "candidate_comparison": comparisons,
        "selected_candidate": selected_name,
        "selection_metric": "require grouped OOF validation F1 >= 0.85, then maximize fixed grouped template-shift development F1, accuracy, and lower FPR",
        "best_fold_f1_mean": best["fold_f1_mean"],
        "minimum_grouped_oof_validation_f1": minimum_validation_f1,
        "grouped_diagnostic_used_for_selection": True,
        "grouped_diagnostic_role": "development robustness benchmark; after-metric is selection-aware",
        "external_used_for_selection": False,
    }, reports_dir / "model_comparison.json")
    (reports_dir / "training_summary.md").write_text(
        "\n".join([
            "# Template-Robust Training Summary", "",
            f"Generated: {generated_at}",
            f"Selected candidate: `{selected_name}`",
            "Decision threshold: `0.50` (fixed; not tuned)",
            f"Development rows: {len(development)}; reserved grouped diagnostic rows: {len(diagnostic)}.",
            f"Grouped OOF validation F1: {validation_metrics.f1:.4f}; FPR: {validation_metrics.false_positive_rate:.4f}; FNR: {validation_metrics.false_negative_rate:.4f}.",
            f"Fixed grouped diagnostic F1: {diagnostic_metrics.f1:.4f}; FPR: {diagnostic_metrics.false_positive_rate:.4f}; FNR: {diagnostic_metrics.false_negative_rate:.4f}.",
            "External evaluation is intentionally absent until the winner is locked.",
            "This remains an academic baseline, not production-grade protection.", "",
        ]), encoding="utf-8",
    )
    split_summary = SplitSummary(train_rows=len(development), validation_rows=len(development), test_rows=len(diagnostic))
    return TrainingSummary(
        model_version=bundle["model_version"],
        preprocessing_version=bundle["preprocessing_version"],
        dataset_summary=summary,
        split_summary=split_summary,
        validation_metrics=validation_metrics,
        test_metrics=diagnostic_metrics,
        selected_threshold=FIXED_THRESHOLD,
        model_path=str(model_path),
        metadata_path=str(reports_dir / "metadata.json"),
    )


def _cross_validated_probabilities(pipeline: Pipeline, frame: pd.DataFrame, random_state: int) -> list[float]:
    from sklearn.base import clone

    labels = frame["label"].astype(int).tolist()
    texts = frame["text"].tolist()
    groups = frame["template_group"].astype(str).tolist()
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    probabilities = np.zeros(len(frame), dtype=float)
    for train_indices, validation_indices in splitter.split(frame, labels, groups):
        fold = clone(pipeline)
        fold.fit([texts[index] for index in train_indices], [labels[index] for index in train_indices])
        probabilities[validation_indices] = _probabilities(fold, [texts[index] for index in validation_indices])
    return probabilities.tolist()
