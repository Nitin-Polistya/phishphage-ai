"""Training entrypoints for the PhishPhage ML baseline."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .config import MLConfig
from .dataset import prepare_dataset, split_dataset
from .evaluation import evaluate_predictions, write_metrics_json
from .schemas import TrainingSummary


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


def train_model(dataset_path: str | Path, model_output: str | Path, metrics_output: str | Path, config: MLConfig | None = None) -> TrainingSummary:
    cfg = config or MLConfig(model_output=Path(model_output), metrics_output=Path(metrics_output))
    prepared = prepare_dataset(dataset_path)
    train_frame, valid_frame, test_frame, split_summary = split_dataset(prepared.dataframe, random_state=cfg.random_state)

    pipeline = build_pipeline(cfg)
    pipeline.fit(train_frame["text"].tolist(), train_frame["label"].tolist())

    valid_pred = pipeline.predict(valid_frame["text"].tolist())
    valid_proba = _positive_class_probability(pipeline, valid_frame["text"].tolist())
    test_pred = pipeline.predict(test_frame["text"].tolist())
    test_proba = _positive_class_probability(pipeline, test_frame["text"].tolist())

    validation_metrics = evaluate_predictions(valid_frame["label"].tolist(), valid_pred.tolist() if hasattr(valid_pred, "tolist") else list(valid_pred), valid_proba)
    test_metrics = evaluate_predictions(test_frame["label"].tolist(), test_pred.tolist() if hasattr(test_pred, "tolist") else list(test_pred), test_proba)

    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline": pipeline,
        "model_version": cfg.model_version,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "preprocessing_version": cfg.preprocessing_version,
        "feature_config": {
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
        },
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_dataset_summary": asdict(prepared.summary),
        "evaluation_metrics": {
            "validation": asdict(validation_metrics),
            "test": asdict(test_metrics),
        },
    }
    joblib.dump(bundle, model_path)

    metrics_payload = {
        "model_version": cfg.model_version,
        "preprocessing_version": cfg.preprocessing_version,
        "dataset_summary": asdict(prepared.summary),
        "split_summary": asdict(split_summary),
        "validation_metrics": asdict(validation_metrics),
        "test_metrics": asdict(test_metrics),
    }
    write_metrics_json(metrics_payload, metrics_output)

    metadata_path = str(Path(metrics_output))
    return TrainingSummary(
        model_version=cfg.model_version,
        preprocessing_version=cfg.preprocessing_version,
        dataset_summary=prepared.summary,
        split_summary=split_summary,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        model_path=str(model_path),
        metadata_path=metadata_path,
    )
