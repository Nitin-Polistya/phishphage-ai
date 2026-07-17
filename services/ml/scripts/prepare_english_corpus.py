"""Parse verified local sources into isolated, provenance-rich JSONL pools."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.acquisition import (
    iter_rfc822_records,
    load_source_registry,
    parse_external_validation,
    parse_zenodo_phishing_positive,
    verify_expected_checksum,
    write_jsonl,
)


def _prepare_source(source, path: Path) -> tuple[list[dict], Counter]:
    if source.id == "zenodo_phishing_nlp_15235123":
        rows, rejected = parse_zenodo_phishing_positive(path, source.id)
        return rows, Counter(rejected)
    if source.role == "external_validation_only":
        rows, rejected = parse_external_validation(path, source.id)
        return rows, Counter(rejected)

    accepted: list[dict] = []
    rejected: Counter = Counter()
    for record in iter_rfc822_records(path, source.id):
        if not record["text"]:
            rejected["empty"] += 1
            continue
        record["label"] = source.assigned_project_label
        record["source_role"] = source.role
        record["record_format"] = "rfc822"
        accepted.append(record)
    return accepted, rejected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=ROOT / "dataset_sources.json", type=Path)
    parser.add_argument("--raw-root", default=ROOT / "data" / "raw", type=Path)
    parser.add_argument("--external-root", default=ROOT / "data" / "external" / "raw", type=Path)
    parser.add_argument("--core-output", default=ROOT / "data" / "interim" / "core_candidates.jsonl", type=Path)
    parser.add_argument("--spam-output", default=ROOT / "data" / "interim" / "generic_spam_hard_negatives.jsonl", type=Path)
    parser.add_argument("--external-output", default=ROOT / "data" / "external" / "interim" / "validation_candidates.jsonl", type=Path)
    parser.add_argument("--audit-output", default=ROOT / "data" / "interim" / "preparation_audit.json", type=Path)
    args = parser.parse_args()

    registry, sources = load_source_registry(args.registry)
    core: list[dict] = []
    generic_spam: list[dict] = []
    external: list[dict] = []
    source_audit: list[dict] = []
    for source in sources.values():
        audit = {
            "source_id": source.id,
            "status": source.status,
            "role": source.role,
            "license": source.license,
            "original_label_meaning": source.original_label_meaning,
            "assigned_project_label": source.assigned_project_label,
            "accepted_samples": 0,
            "rejected_samples": 0,
            "rejection_reasons": {},
            "language_distribution": "pending audit_languages.py",
        }
        if source.status != "approved" or not source.archive_filename:
            audit["outcome"] = "not_used"
            audit["reason"] = source.block_reason or source.status
            source_audit.append(audit)
            continue
        base = args.external_root if source.role == "external_validation_only" else args.raw_root
        path = base / source.archive_filename
        if not path.exists():
            audit.update({"outcome": "missing", "reason": str(path)})
            source_audit.append(audit)
            continue
        try:
            verify_expected_checksum(path, source.expected_checksum)
            rows, rejected = _prepare_source(source, path)
        except (ValueError, OSError) as exc:
            audit.update({"outcome": "rejected", "reason": str(exc)})
            source_audit.append(audit)
            continue
        if source.role == "external_validation_only":
            external.extend(rows)
        elif source.role == "generic_spam_hard_negative":
            generic_spam.extend(rows)
        else:
            core.extend(row for row in rows if row.get("label") in (0, 1))
        audit.update({
            "outcome": "prepared",
            "accepted_samples": len(rows),
            "rejected_samples": sum(rejected.values()),
            "rejection_reasons": dict(rejected),
        })
        source_audit.append(audit)

    write_jsonl(args.core_output, core)
    write_jsonl(args.spam_output, generic_spam)
    write_jsonl(args.external_output, external)
    class_counts = Counter(row["label"] for row in core)
    report = {
        "schema_version": 1,
        "registry_audited_on": registry["audited_on"],
        "sources": source_audit,
        "core_candidate_counts": {"legitimate": class_counts[0], "phishing": class_counts[1]},
        "generic_spam_hard_negative_count": len(generic_spam),
        "external_validation_count": len(external),
        "external_used_for_training": False,
        "ready_for_language_audit": bool(core),
        "ready_for_training": False,
        "training_block_reason": "source audit and corpus statistics require human review",
    }
    args.audit_output.parent.mkdir(parents=True, exist_ok=True)
    args.audit_output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

