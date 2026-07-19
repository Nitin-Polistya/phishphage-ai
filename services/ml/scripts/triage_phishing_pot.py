"""Generate advisory privacy-safe triage reports for the staged pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phishshield_ml.phishing_pot_triage import write_triage_reports


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=root / "reports" / "phishing_pot_pilot_001")
    parser.add_argument("--config", type=Path, default=root / "config" / "acquisition_batches" / "phishing_pot_pilot_001.json")
    args = parser.parse_args()
    policy = json.loads(args.config.read_text(encoding="utf-8"))
    report = write_triage_reports(root, args.output_dir, policy=policy)
    print(f"Triaged {report['candidate_count']} candidates; {report['manual_review_count']} require review; promotion remains blocked.")


if __name__ == "__main__":
    main()
