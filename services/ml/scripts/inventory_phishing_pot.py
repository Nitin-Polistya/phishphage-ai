"""Build privacy-safe aggregate inventory reports from derived metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_pilot import load_metadata_jsonl, write_source_inventory


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True, help="Metadata-only JSONL; message bodies are rejected")
    parser.add_argument("--source-commit-sha")
    parser.add_argument("--output-dir", type=Path, default=root / "reports" / "phishing_pot_pilot_001")
    args = parser.parse_args()
    records = load_metadata_jsonl(args.metadata)
    report = write_source_inventory(records, args.output_dir, source_commit_sha=args.source_commit_sha)
    print(f"Inventoried {report['total_eml_files']} metadata records without emitting message content.")


if __name__ == "__main__":
    main()
