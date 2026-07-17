"""CLI for evaluating a saved ML baseline model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from phishshield_ml.dataset import load_and_validate_dataset
from phishshield_ml.evaluation import evaluate_predictions, write_metrics_json
from phishshield_ml.inference import load_model_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate the PhishPhage ML baseline")
    parser.add_argument("--dataset", required=True, help="Path to a labeled CSV dataset")
    parser.add_argument("--model", required=True, help="Path to a saved model bundle")
    parser.add_argument("--output", required=True, help="Path to write evaluation JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    frame = load_and_validate_dataset(args.dataset)
    bundle = load_model_bundle(args.model)
    pipeline = bundle.pipeline
    probabilities = pipeline.predict_proba(frame["text"].tolist())[:, 1].tolist()
    predictions = [int(probability >= bundle.decision_threshold) for probability in probabilities]
    metrics = evaluate_predictions(frame["label"].tolist(), predictions, probabilities)
    payload = {
        "model_version": bundle.model_version,
        "dataset_rows": len(frame),
        "decision_threshold": bundle.decision_threshold,
        "metrics": json.loads(json.dumps(metrics, default=lambda o: o.__dict__)),
    }
    write_metrics_json(payload, args.output)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
