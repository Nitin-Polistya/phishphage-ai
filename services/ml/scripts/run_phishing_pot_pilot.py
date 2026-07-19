"""Run the authorized local-only Phishing Pot staging pilot."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_run import run_pilot


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository-email-dir", type=Path,
        default=root / "data/external/phishing_pot/repository/email",
    )
    parser.add_argument(
        "--metadata", type=Path,
        default=root / "data/external/phishing_pot/metadata/source_metadata.jsonl",
    )
    parser.add_argument(
        "--output-dir", type=Path,
        default=root / "reports/phishing_pot_pilot_001",
    )
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--reuse-metadata", action="store_true",
        help="Reuse a complete atomic metadata scan after verifying it matches the local checkout",
    )
    args = parser.parse_args()
    result = run_pilot(
        root, args.repository_email_dir, args.metadata, args.output_dir,
        workers=args.workers, reuse_metadata=args.reuse_metadata,
    )
    print(
        f"Scanned {result['scan']['scanned']} EML files; selected "
        f"{result['selection']['selected_count']} for manual review; promotion remains blocked."
    )


if __name__ == "__main__":
    main()
