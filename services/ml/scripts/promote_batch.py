"""Preview or explicitly confirm promotion from staging into a processed CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.controlled_acquisition import promote_batch


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--confirm", action="store_true")
    parser.add_argument("--destination", type=Path, default=root / "data/processed/english_core_v3.csv")
    args = parser.parse_args()
    report = promote_batch(root, args.batch_id, args.destination, confirm=args.confirm)
    action = "Promoted" if report["promotion_performed"] else "Previewed"
    print(f"{action} {report['approved_rows']} approved rows; blockers={len(report['blockers'])}.")


if __name__ == "__main__":
    main()
