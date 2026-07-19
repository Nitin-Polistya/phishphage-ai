"""Generate the mandatory safety preflight before any pilot acquisition."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.phishing_pot_pilot import write_preflight_validation


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir", type=Path,
        default=root / "reports" / "phishing_pot_pilot_001",
    )
    args = parser.parse_args()
    report = write_preflight_validation(root, args.output_dir)
    print(f"Preflight passed {sum(item['passed'] for item in report['checks'])}/{len(report['checks'])} checks; promotion remains blocked.")


if __name__ == "__main__":
    main()
