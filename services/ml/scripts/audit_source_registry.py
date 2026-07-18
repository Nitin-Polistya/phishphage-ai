"""Audit controlled source metadata and generate manual review packets."""

from pathlib import Path

from phishshield_ml.source_review import write_source_registry_audit, write_source_review_packets


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    audit = write_source_registry_audit(
        root, root / "reports/source_registry_audit.json", root / "reports/source_registry_audit.md",
    )
    packets = write_source_review_packets(root, root / "reports/source_reviews")
    print(f"Audited {audit['summary']['total_sources']} sources; wrote {len(packets)} review packets.")


if __name__ == "__main__":
    main()
