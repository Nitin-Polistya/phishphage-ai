"""Legacy Step 1 converter retained for compatibility.

Step 2 production of the English-first corpus uses scripts/build_english_corpus.py.
Spanish corpus mixing is intentionally rejected here to prevent accidental reuse.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from phishshield_ml.preprocessing import normalize_email_text


SOURCE_LABELS = {"Safe Email": 0, "Phishing Email": 1}


def prepare_source(source: Path, output: Path, summary_output: Path, spaphish_source: Path | None = None) -> dict:
    frame = pd.read_csv(source)
    required = {"Email Text", "Email Type"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Missing source columns: {sorted(missing)}")

    input_counts = frame["Email Type"].value_counts(dropna=False).to_dict()
    unsupported = sorted(set(frame["Email Type"].dropna()) - set(SOURCE_LABELS))
    if unsupported:
        raise ValueError(f"Unsupported source labels: {unsupported}")

    zenodo_prepared = pd.DataFrame({
        "text": frame["Email Text"].map(normalize_email_text),
        "label": frame["Email Type"].map(SOURCE_LABELS),
    })
    source_summaries = [{
        "title": "Phishing validation emails dataset",
        "doi": "10.5281/zenodo.13474746",
        "license": "CC BY 4.0",
        "language": "English",
        "input_rows": int(len(frame)),
        "input_class_counts": {
            "legitimate": int(input_counts.get("Safe Email", 0)),
            "phishing": int(input_counts.get("Phishing Email", 0)),
        },
    }]
    frames = [zenodo_prepared]
    if spaphish_source is not None:
        raise ValueError("SpaPhish mixing was retired in Step 2; use build_english_corpus.py")

    prepared = pd.concat(frames, ignore_index=True)
    empty_mask = prepared["text"].eq("") | prepared["label"].isna()
    empty_rows_removed = int(empty_mask.sum())
    prepared = prepared.loc[~empty_mask].copy()
    duplicate_rows_removed = int(prepared.duplicated(subset=["text"], keep="first").sum())
    prepared = prepared.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    prepared["label"] = prepared["label"].astype(int)

    output.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(output, index=False)
    output_counts = prepared["label"].value_counts().to_dict()
    summary = {
        "sources": source_summaries,
        "input": {
            "rows": int(sum(item["input_rows"] for item in source_summaries)),
            "class_counts": {
                "legitimate": int(sum(item["input_class_counts"]["legitimate"] for item in source_summaries)),
                "phishing": int(sum(item["input_class_counts"]["phishing"] for item in source_summaries)),
            },
        },
        "cleaning": {
            "empty_rows_removed": empty_rows_removed,
            "exact_duplicate_texts_removed": duplicate_rows_removed,
        },
        "output": {
            "rows": int(len(prepared)),
            "class_counts": {
                "legitimate": int(output_counts.get(0, 0)),
                "phishing": int(output_counts.get(1, 0)),
            },
            "columns": ["text", "label"],
            "label_mapping": {"legitimate": 0, "phishing": 1},
        },
    }
    summary_output.parent.mkdir(parents=True, exist_ok=True)
    summary_output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare the selected phishing-email dataset")
    parser.add_argument("--source", required=True)
    parser.add_argument("--spaphish-source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = prepare_source(
        Path(args.source),
        Path(args.output),
        Path(args.summary_output),
        Path(args.spaphish_source) if args.spaphish_source else None,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
