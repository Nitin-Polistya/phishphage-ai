"""Verify local source files, official checksums, and archive safety."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.acquisition import (
    compute_checksums,
    load_source_registry,
    safe_archive_members,
    verify_expected_checksum,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=ROOT / "dataset_sources.json", type=Path)
    parser.add_argument("--raw-root", default=ROOT / "data" / "raw", type=Path)
    parser.add_argument("--external-root", default=ROOT / "data" / "external", type=Path)
    parser.add_argument("--output", default=ROOT / "data" / "interim" / "verification_report.json", type=Path)
    parser.add_argument("--strict", action="store_true", help="Fail if any approved file is absent")
    args = parser.parse_args()

    registry, sources = load_source_registry(args.registry)
    results: list[dict] = []
    failures = 0
    for source in sources.values():
        base = args.external_root if source.role == "external_validation_only" else args.raw_root
        path = base / source.archive_filename if source.archive_filename else None
        result = {
            "source_id": source.id,
            "official_url": source.official_page,
            "license": source.license,
            "status": source.status,
            "role": source.role,
            "archive_filename": source.archive_filename,
            "original_label_meaning": source.original_label_meaning,
            "assigned_project_label": source.assigned_project_label,
            "language_scope": source.language_scope,
            "block_reason": source.block_reason,
        }
        if source.status != "approved":
            result["verification"] = "not_used"
        elif path is None or not path.exists():
            result["verification"] = "missing"
            if args.strict:
                failures += 1
        else:
            try:
                checksums = verify_expected_checksum(path, source.expected_checksum)
                members = safe_archive_members(path)
                result.update({
                    "verification": "verified",
                    "bytes": path.stat().st_size,
                    "checksums": checksums,
                    "archive_member_count": len(members),
                })
            except (ValueError, OSError) as exc:
                result.update({"verification": "failed", "reason": str(exc), "checksums": compute_checksums(path)})
                failures += 1
        results.append(result)

    report = {
        "schema_version": 1,
        "registry_audited_on": registry["audited_on"],
        "sources": results,
        "verified_approved_sources": sum(item.get("verification") == "verified" for item in results),
        "failures": failures,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
