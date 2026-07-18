"""Initialize or validate a local controlled-acquisition batch."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.controlled_acquisition import ingest_batch, initialize_batch


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("init")
    initialize.add_argument("--batch-id", required=True)
    initialize.add_argument("--source-id", required=True)
    initialize.add_argument("--input-filename", required=True)
    initialize.add_argument("--requested-split", default="development_pool")
    initialize.add_argument("--acquisition-date")
    run = subparsers.add_parser("run")
    run.add_argument("--batch-id", required=True)
    run.add_argument("--registry", type=Path, default=root / "config/dataset_source_registry.json")
    args = parser.parse_args()
    if args.command == "init":
        directory = initialize_batch(
            root, args.batch_id, args.source_id, args.input_filename,
            args.requested_split, args.acquisition_date,
        )
        print(f"Initialized {directory}. Place the reviewed source file under raw/ before running ingestion.")
        return
    report = ingest_batch(root, args.batch_id, args.registry)
    print(f"Accepted {report['accepted_rows']} rows for manual review; rejected {report['rejected_rows']} rows.")


if __name__ == "__main__":
    main()
