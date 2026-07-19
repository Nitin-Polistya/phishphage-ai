"""Generate the controlled Phishing Pot weak-label policy dry run."""

from __future__ import annotations

import json
from pathlib import Path

from phishshield_ml.phishing_pot_weak_labels import run_policy_dry_run


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    result = run_policy_dry_run(root)
    summary = {
        "assessed": result["eligibility"]["assessed_pilot_messages"],
        "privacy_sanitized": result["eligibility"]["privacy_sanitized"],
        "privacy_blocked": result["eligibility"]["privacy_blocked"],
        "weak_label_eligible": result["eligibility"]["estimated_weak_label_eligible_rows"],
        "estimated_sampled": result["sampling"]["estimated_final_sampled_rows"],
        "registry_changed": False,
        "training_executed": False,
        "promotion_eligible": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
