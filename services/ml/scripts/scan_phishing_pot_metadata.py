"""Statically scan local Phishing Pot EML files into privacy-safe metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_pilot import write_safe_metadata_jsonl


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=root / "data" / "external" / "phishing_pot" / "repository" / "email",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "external" / "phishing_pot" / "derived" / "safe_metadata.jsonl",
    )
    args = parser.parse_args()
    summary = write_safe_metadata_jsonl(args.source_dir, args.output)
    print(
        f"Scanned {summary['scanned']} EML files: "
        f"{summary['parse_safe']} parse-safe, {summary['unsafe']} unsafe."
    )


if __name__ == "__main__":
    main()
