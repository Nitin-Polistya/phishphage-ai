"""Record one explicit human adjudication for a staged Phishing Pot candidate."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.controlled_acquisition import PILOT_REVIEW_CLASSIFICATIONS
from phishshield_ml.phishing_pot_run import update_pilot_review


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--classification", required=True, choices=sorted(PILOT_REVIEW_CLASSIFICATIONS))
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--phishing-confirmed", action="store_true")
    parser.add_argument("--privacy-checks-passed", action="store_true")
    parser.add_argument("--license-checks-passed", action="store_true")
    parser.add_argument("--grouping-reviewed", action="store_true")
    parser.add_argument("--manual-approved", action="store_true")
    parser.add_argument("--safe-notes", default="")
    parser.add_argument(
        "--queue", type=Path,
        default=root / "reports/phishing_pot_pilot_001/pilot_review_queue.json",
    )
    args = parser.parse_args()
    result = update_pilot_review(
        args.queue, args.candidate_id, args.classification, args.reviewer,
        phishing_confirmed=args.phishing_confirmed,
        privacy_checks_passed=args.privacy_checks_passed,
        license_checks_passed=args.license_checks_passed,
        grouping_reviewed=args.grouping_reviewed,
        manual_approved=args.manual_approved,
        safe_notes=args.safe_notes,
    )
    print(f"Recorded {result['classification']} for {result['candidate_id']}.")


if __name__ == "__main__":
    main()
