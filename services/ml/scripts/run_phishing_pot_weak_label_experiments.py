"""Run the isolated Phishing Pot weak-label comparison suite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services" / "ml" / "src"))

from phishshield_ml.weak_label_experiments import EXPERIMENT_IDS, run_suite


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "services/ml/config/experiments/phishing_pot_weak_label_comparison_v1.json"))
    selection = parser.add_mutually_exclusive_group(required=False)
    selection.add_argument("--experiment", choices=EXPERIMENT_IDS, action="append")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--force-retrain", action="store_true")
    args = parser.parse_args()
    if not args.verify_only and not args.all and not args.experiment:
        parser.error("choose --all, --experiment, or --verify-only")
    experiments = list(EXPERIMENT_IDS) if args.all else (args.experiment or [])
    result = run_suite(args.config, experiments, verify_only=args.verify_only, force=args.force_retrain)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
