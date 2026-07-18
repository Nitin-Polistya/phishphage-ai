"""Record one explicit manual-review decision in a staging batch."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.controlled_acquisition import REVIEW_STATUS_ENUM, update_review


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--status", required=True, choices=sorted(REVIEW_STATUS_ENUM))
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--notes", default="")
    parser.add_argument("--approved-label", type=int, choices=[0, 1])
    parser.add_argument("--approved-category")
    parser.add_argument("--approved-campaign")
    parser.add_argument("--approved-template")
    parser.add_argument("--privacy-checked", action="store_true")
    parser.add_argument("--license-checked", action="store_true")
    args = parser.parse_args()
    review = update_review(
        root, args.batch_id, args.sample_id, args.status, args.reviewer, args.notes,
        args.approved_label, args.approved_category, args.approved_campaign,
        args.approved_template, args.privacy_checked, args.license_checked,
    )
    print(f"Recorded {review['review_status']} for {review['sample_id']}.")


if __name__ == "__main__":
    main()
