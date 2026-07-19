"""Run the safe deterministic Phishing Pot Batch 002 dry run."""

from __future__ import annotations

import json
from pathlib import Path

from phishshield_ml.phishing_pot_batch002 import run_batch002_dry_run


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    result = run_batch002_dry_run(root)
    summary = {
        "selected": result["selection"]["selected_count"],
        "safely_parsed": result["selection"]["safely_parsed_selected"],
        "privacy_sanitized": result["privacy"]["privacy_status_counts"].get("privacy_sanitized", 0),
        "privacy_blocked": result["privacy"]["privacy_status_counts"].get("privacy_blocked_irreducible", 0),
        "weak_label_eligible": result["eligibility"]["eligible_rows"],
        "proposed_sampled": result["sampling"]["proposed_final_sampled_rows"],
        "estimated_source_share": result["sampling"]["estimated_source_share"],
        "training_executed": False,
        "promotion_eligible": False,
        "source_approved": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
