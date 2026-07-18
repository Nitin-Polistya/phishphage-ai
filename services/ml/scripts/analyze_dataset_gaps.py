"""Generate deterministic taxonomy gap reports."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.dataset_gaps import write_gap_analysis


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path, default=root / "reports/dataset_gap_analysis.json")
    parser.add_argument("--markdown-output", type=Path, default=root / "reports/dataset_gap_analysis.md")
    args = parser.parse_args()
    analysis = write_gap_analysis(root, args.json_output, args.markdown_output)
    print(f"Analyzed {len(analysis['categories'])} taxonomy categories.")


if __name__ == "__main__":
    main()
