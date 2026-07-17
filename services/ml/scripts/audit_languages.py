"""Audit every staged sample and remove non-English rows from the core pool."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.acquisition import assert_not_external_path, read_jsonl, write_jsonl
from phishshield_ml.dataset import estimate_language


def _audit(rows: list[dict], *, filter_to_english: bool) -> tuple[list[dict], list[dict], dict]:
    accepted: list[dict] = []
    rejected: list[dict] = []
    distributions: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        language, confidence = estimate_language(row["text"])
        enriched = {**row, "language": language, "language_confidence": round(confidence, 6)}
        distributions[row["source"]][language] += 1
        if filter_to_english and language != "en":
            rejected.append(enriched)
        else:
            accepted.append(enriched)
    summary = {
        "input_samples": len(rows),
        "accepted_samples": len(accepted),
        "rejected_samples": len(rejected),
        "language_distribution_by_source": {
            source: dict(sorted(counts.items())) for source, counts in sorted(distributions.items())
        },
    }
    return accepted, rejected, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=ROOT / "dataset_sources.json", type=Path)
    parser.add_argument("--download-manifest", default=ROOT / "data" / "interim" / "download_manifest.json", type=Path)
    parser.add_argument("--verification-report", default=ROOT / "data" / "interim" / "verification_report.json", type=Path)
    parser.add_argument("--preparation-audit", default=ROOT / "data" / "interim" / "preparation_audit.json", type=Path)
    parser.add_argument("--core-input", default=ROOT / "data" / "interim" / "core_candidates.jsonl", type=Path)
    parser.add_argument("--core-output", default=ROOT / "data" / "interim" / "english_candidates.jsonl", type=Path)
    parser.add_argument("--rejected-output", default=ROOT / "data" / "interim" / "non_english_rejected.jsonl", type=Path)
    parser.add_argument("--external-input", default=ROOT / "data" / "external" / "interim" / "validation_candidates.jsonl", type=Path)
    parser.add_argument("--external-output", default=ROOT / "data" / "external" / "interim" / "validation_language_audit.jsonl", type=Path)
    parser.add_argument("--external-csv-output", default=ROOT / "data" / "external" / "processed" / "validation.csv", type=Path)
    parser.add_argument("--report", default=ROOT / "data" / "interim" / "language_audit.json", type=Path)
    args = parser.parse_args()

    assert_not_external_path(args.core_input)
    core_rows = read_jsonl(args.core_input) if args.core_input.exists() else []
    accepted, rejected, core_summary = _audit(core_rows, filter_to_english=True)
    write_jsonl(args.core_output, accepted)
    write_jsonl(args.rejected_output, rejected)

    external_rows = read_jsonl(args.external_input) if args.external_input.exists() else []
    external_audited, _, external_summary = _audit(external_rows, filter_to_english=False)
    write_jsonl(args.external_output, external_audited)
    args.external_csv_output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(external_audited).to_csv(args.external_csv_output, index=False)

    class_counts = Counter(row["label"] for row in accepted)
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    download_manifest = json.loads(args.download_manifest.read_text(encoding="utf-8")) if args.download_manifest.exists() else {"downloads": []}
    verification = json.loads(args.verification_report.read_text(encoding="utf-8")) if args.verification_report.exists() else {"sources": []}
    preparation = json.loads(args.preparation_audit.read_text(encoding="utf-8")) if args.preparation_audit.exists() else {"sources": []}
    downloads_by_id = {item["source_id"]: item for item in download_manifest["downloads"]}
    verification_by_id = {item["source_id"]: item for item in verification["sources"]}
    preparation_by_id = {item["source_id"]: item for item in preparation["sources"]}
    language_by_source = {
        **core_summary["language_distribution_by_source"],
        **external_summary["language_distribution_by_source"],
    }
    source_records = []
    for source in registry["sources"]:
        source_id = source["id"]
        downloaded = downloads_by_id.get(source_id, {})
        verified = verification_by_id.get(source_id, {})
        prepared = preparation_by_id.get(source_id, {})
        source_records.append({
            "source_id": source_id,
            "official_url": source["official_page"],
            "download_url": source["download_url"],
            "license": source["license"],
            "status": source["status"],
            "block_reason": source.get("block_reason"),
            "checksum_expected": source["expected_checksum"],
            "checksums_computed": downloaded.get("checksums", verified.get("checksums")),
            "download_date_utc": downloaded.get("download_date_utc"),
            "archive_filename": source["archive_filename"],
            "original_label_meaning": source["original_label_meaning"],
            "assigned_project_label": source["assigned_project_label"],
            "role": source["role"],
            "language_distribution": language_by_source.get(source_id, {}),
            "accepted_samples": prepared.get("accepted_samples", 0),
            "rejected_samples": prepared.get("rejected_samples", 0),
            "rejection_reasons": prepared.get("rejection_reasons", {}),
            "verification": verified.get("verification", "not_run"),
        })
    report = {
        "schema_version": 1,
        "registry_audited_on": registry["audited_on"],
        "sources": source_records,
        "core": {
            **core_summary,
            "class_counts_after_language_gate": {
                "legitimate": class_counts[0],
                "phishing": class_counts[1],
            },
            "gate": "language == en",
        },
        "external_validation": {
            **external_summary,
            "filtered": False,
            "used_for_training": False,
        },
        "ready_for_training": False,
        "review_required": True,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
