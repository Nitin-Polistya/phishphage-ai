"""Validate Batch 001 before any acquisition is allowed."""

from pathlib import Path

from phishshield_ml.source_review import write_batch_readiness


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    report = write_batch_readiness(
        root, root / "reports/batch_001_readiness.json", root / "reports/batch_001_readiness.md",
    )
    print(report["conclusion"])


if __name__ == "__main__":
    main()
