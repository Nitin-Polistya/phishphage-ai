"""Run the source-membership artifact inventory (no classifier training)."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services/ml/src"))
from phishshield_ml.artifact_reduction import run_artifact_reduction

parser = argparse.ArgumentParser()
parser.add_argument("--config", default=str(ROOT / "services/ml/config/experiments/phishing_pot_weak_label_comparison_v1.json"))
parser.add_argument("--output-dir", default=None)
parser.add_argument("--max-iterations", type=int, default=5)
args = parser.parse_args()
print(json.dumps(run_artifact_reduction(args.config, args.output_dir, args.max_iterations), indent=2, sort_keys=True))
