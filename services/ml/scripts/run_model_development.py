from __future__ import annotations

import argparse
import json

from phishshield_ml.model_development import run_phase_c


def main() -> None:
    parser = argparse.ArgumentParser(description="Run frozen Phase C model development")
    parser.add_argument("--registry", default="services/ml/config/models/phase_c_v1.json")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run_phase_c(args.registry, force=args.force), indent=2))


if __name__ == "__main__":
    main()
