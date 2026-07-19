"""Select exactly 22 provisional Phishing Pot candidates from safe metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_pilot import (
    SELECTION_SEED,
    load_metadata_jsonl,
    write_candidate_selection,
)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True, help="Metadata-only JSONL; message bodies are rejected")
    parser.add_argument("--seed", default=SELECTION_SEED)
    parser.add_argument("--output-dir", type=Path, default=root / "reports" / "phishing_pot_pilot_001")
    args = parser.parse_args()
    records = load_metadata_jsonl(args.metadata)
    report = write_candidate_selection(records, args.output_dir, seed=args.seed)
    print(f"Selected {report['selected_count']} provisional candidates; all await manual review.")


if __name__ == "__main__":
    main()
