"""Generate the expected blocked promotion dry-run for the staging pilot."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_run import write_blocked_promotion_preview


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--review-queue", type=Path,
        default=root / "reports/phishing_pot_pilot_001/pilot_review_queue.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=root / "reports/phishing_pot_pilot_001/blocked_promotion_preview.json",
    )
    args = parser.parse_args()
    report = write_blocked_promotion_preview(root, args.review_queue, args.output)
    print(f"Promotion {report['result']}: {', '.join(report['blockers'])}")


if __name__ == "__main__":
    main()
