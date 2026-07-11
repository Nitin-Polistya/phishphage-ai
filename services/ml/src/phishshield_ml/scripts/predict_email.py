"""CLI for local prediction using a saved ML bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.inference import LocalInferenceService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Predict phishing likelihood for raw text")
    parser.add_argument("--model", required=True, help="Path to a saved model bundle")
    parser.add_argument("--text", help="Raw email text to classify")
    parser.add_argument("--file", help="Path to a text file containing the raw email text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.text) == bool(args.file):
        parser.error("Provide exactly one of --text or --file")
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    else:
        text = args.text
    service = LocalInferenceService(args.model)
    result = service.predict(text)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
