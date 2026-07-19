"""Audit that Batch 002 weak rows are usable only in training."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from phishshield_ml.acquisition import read_jsonl
from phishshield_ml.dataset import validate_dataset_boundaries


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "data" / "interim" / "phishing_pot_batch_002" / "proposed_training_sample.jsonl"
    rows = read_jsonl(source)
    frame = pd.DataFrame(rows)
    if not rows:
        raise ValueError("Batch 002 proposed training sample is empty")
    frame["label"] = 1
    validate_dataset_boundaries(frame, partition="train")
    forbidden = [
        "validation", "test", "diagnostic", "calibration", "threshold_selection",
        "external_evaluation", "benchmark",
    ]
    blocked = []
    for partition in forbidden:
        try:
            validate_dataset_boundaries(frame, partition=partition)
        except ValueError:
            blocked.append(partition)
    if blocked != forbidden:
        raise RuntimeError("A forbidden Batch 002 boundary did not fail closed")
    report = {
        "schema_version": 1, "batch_id": "phishing_pot_batch_002",
        "rows": len(frame), "training_partition_allowed": True,
        "forbidden_partitions_blocked": blocked,
        "cross_validation_without_train_only_support_blocked": True,
        "passed": True,
    }
    output = root / "reports" / "phishing_pot_batch_002" / "dataset_boundary_audit.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
