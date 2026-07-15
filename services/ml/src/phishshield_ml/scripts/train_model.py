"""CLI for training the ML baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phishshield_ml.config import MLConfig
from phishshield_ml.training import train_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the PhishPhage ML baseline")
    parser.add_argument("--dataset", required=True, help="Path to a labeled CSV dataset")
    parser.add_argument("--model-output", required=True, help="Path to write the model bundle")
    parser.add_argument("--metrics-output", required=True, help="Path to write metrics JSON")
    parser.add_argument("--min-df", type=int, default=MLConfig.min_df)
    parser.add_argument("--max-df", type=float, default=MLConfig.max_df)
    parser.add_argument("--max-features", type=int, default=MLConfig.max_features)
    parser.add_argument("--max-iter", type=int, default=MLConfig.max_iter)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = MLConfig(
        min_df=args.min_df,
        max_df=args.max_df,
        max_features=args.max_features,
        max_iter=args.max_iter,
        model_output=Path(args.model_output),
        metrics_output=Path(args.metrics_output),
    )
    summary = train_model(args.dataset, args.model_output, args.metrics_output, config=config)
    print(json.dumps({
        "model_version": summary.model_version,
        "model_path": summary.model_path,
        "metadata_path": summary.metadata_path,
        "train_rows": summary.split_summary.train_rows,
        "validation_rows": summary.split_summary.validation_rows,
        "test_rows": summary.split_summary.test_rows,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
