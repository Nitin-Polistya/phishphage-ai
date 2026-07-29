from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_gold_standard_dataset.py"
SPEC = importlib.util.spec_from_file_location("build_gold_standard_dataset", SCRIPT)
assert SPEC and SPEC.loader
curator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = curator
SPEC.loader.exec_module(curator)


RAW_EMAIL = """From: sender@example.com
To: reviewer@example.com
Subject: Routine update

The routine update is attached for review.
"""


def candidate(tmp_path: Path, name: str = "message.eml") -> dict:
    path = tmp_path / name
    path.write_text(RAW_EMAIL, encoding="utf-8")
    records, _ = curator.scan_candidates([tmp_path])
    assert records
    return records[0]


def make_adjudicated(record: dict) -> dict:
    result = dict(record)
    result.update(
        {
            "expected_class": "safe",
            "campaign": "routine-updates",
            "sample_date": "2026-07-29",
            "language": "en",
            "review_status": "adjudicated",
            "reviewer_count": 2,
            "adjudication_status": "complete",
            "labeling_notes": "Two independent reviews completed.",
            "privacy_status": "pass",
            "reviewer_1_label": "safe",
            "reviewer_2_label": "safe",
            "adjudicated_label": "safe",
            "adjudication_notes": "Evidence supports a routine update.",
            "final_reviewer": "reviewer-a",
            "final_review_date": "2026-07-29",
            "overlap_status": "pass",
            "duplicate_status": "pass",
            "content_exists": True,
            "content_hash_stable": True,
            "training_overlap": False,
            "development_overlap": False,
        }
    )
    return result


def test_schema_is_versioned_and_has_three_class_vocabulary() -> None:
    schema = json.loads(curator.SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["$id"].endswith("/1.0")
    assert schema["properties"]["expected_class"]["enum"] == ["safe", "suspicious", "phishing", None]
    assert set(
        {
            "sample_id", "source_dataset", "source_record_id", "campaign", "sample_date",
            "language", "review_status", "privacy_status", "content_location", "content_hash",
        }
    ).issubset(schema["required"])


def test_stable_hash_normalizes_line_endings() -> None:
    assert curator.stable_content_hash("Subject: x\r\n\r\nBody\r\n") == curator.stable_content_hash("Subject: x\n\nBody\n")


def test_redaction_removes_sensitive_values() -> None:
    redacted = curator._redact_text("Call +1 (555) 123-4567 or a@b.example; https://example.invalid/tok; C:\\private\\mail.eml")

    assert "@" not in redacted
    assert "https://" not in redacted
    assert "555" not in redacted
    assert "C:\\private" not in redacted


def test_scan_never_uses_source_label_as_ground_truth(tmp_path: Path) -> None:
    path = tmp_path / "phishing_filename.eml"
    path.write_text(RAW_EMAIL, encoding="utf-8")
    sidecar = tmp_path / "metadata.json"
    sidecar.write_text(json.dumps({"path": path.name, "label": "phishing", "expected_class": "phishing"}), encoding="utf-8")

    records, _ = curator.scan_candidates([tmp_path])

    assert len(records) == 1
    assert records[0]["expected_class"] is None
    assert records[0]["review_status"] == "unreviewed"


def test_invalid_labels_duplicate_ids_and_missing_campaign_are_rejected(tmp_path: Path) -> None:
    record = candidate(tmp_path)
    invalid = dict(record, expected_class="spam", campaign="")
    report = curator.validate_manifest([invalid, dict(record)])

    assert not report["valid"]
    reasons = " ".join(issue for error in report["errors"] for issue in error["issues"])
    assert "invalid expected_class" in reasons
    assert "missing campaign" in reasons
    assert "duplicate sample_id" in reasons


def test_unknown_date_is_explicitly_allowed_before_final_review(tmp_path: Path) -> None:
    record = candidate(tmp_path)

    assert "missing field: sample_date" not in curator.validate_record(record)
    assert record["sample_date"] == "unknown"


def test_one_reviewer_is_provisional_and_two_reviewers_can_adjudicate(tmp_path: Path) -> None:
    record = candidate(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "sample_id,reviewer_1_label,reviewer_1_confidence,reviewer_1_notes,reviewer_2_label,reviewer_2_confidence,reviewer_2_notes,adjudicated_label,disagreement_reason,adjudication_notes,final_reviewer,final_review_date\n"
        f"{record['sample_id']},safe,high,looks routine,,,,,,,,\n",
        encoding="utf-8",
    )
    provisional, errors = curator.apply_labels([record], labels)

    assert not errors
    assert provisional[0]["review_status"] == "provisional"
    assert provisional[0]["expected_class"] is None

    labels.write_text(
        "sample_id,reviewer_1_label,reviewer_1_confidence,reviewer_1_notes,reviewer_2_label,reviewer_2_confidence,reviewer_2_notes,adjudicated_label,disagreement_reason,adjudication_notes,final_reviewer,final_review_date\n"
        f"{record['sample_id']},safe,high,looks routine,safe,high,independent review,safe,,adjudicated safely,reviewer-a,2026-07-29\n",
        encoding="utf-8",
    )
    adjudicated, errors = curator.apply_labels([record], labels)

    assert not errors
    assert adjudicated[0]["review_status"] == "adjudicated"
    assert adjudicated[0]["adjudication_status"] == "complete"
    assert adjudicated[0]["expected_class"] == "safe"


def test_final_gate_rejects_pending_privacy_and_absolute_paths(tmp_path: Path) -> None:
    record = make_adjudicated(candidate(tmp_path))
    record["privacy_status"] = "pending"
    record["content_location"] = "C:\\private\\message.eml"

    issues = curator.validate_record(record, final=True)

    assert "privacy review has not passed" in issues
    assert "absolute content path" in issues


def test_public_manifest_is_sorted_and_contains_no_raw_content(tmp_path: Path) -> None:
    first = candidate(tmp_path, "b.eml")
    second = candidate(tmp_path, "a.eml")
    output = tmp_path / "manifest.jsonl"
    curator.write_manifest(output, [first, second])

    lines = output.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert [row["sample_id"] for row in records] == sorted(row["sample_id"] for row in records)
    assert all(not any(key in row for key in curator.RAW_KEYS) for row in records)
    assert all(not any(isinstance(value, str) and value.startswith("C:\\") for value in row.values()) for row in records)


def test_exact_overlap_is_reported(tmp_path: Path) -> None:
    candidate_path = tmp_path / "candidate.eml"
    candidate_path.write_text(RAW_EMAIL, encoding="utf-8")
    records, _ = curator.scan_candidates([candidate_path])

    reference_dir = tmp_path / "reference"
    reference_dir.mkdir()
    (reference_dir / "same.eml").write_text(RAW_EMAIL, encoding="utf-8")
    exact, _ = curator.leakage_audit(records, [reference_dir])

    assert any(row["overlap_type"] == "exact_content_hash" for row in exact)


def test_empty_pilot_withholds_metrics_and_reports_shortfall(tmp_path: Path) -> None:
    output = tmp_path / "pilot"
    result = curator.run_pilot(tmp_path / "empty.jsonl", output, tmp_path / "private.jsonl")

    assert result["status"] == "not_ready"
    assert (output / "readiness.md").exists()
    assert (output / "shortfall.json").exists()
    assert not (output / "metrics.json").exists()


def test_export_locks_only_finally_eligible_records(tmp_path: Path) -> None:
    record = make_adjudicated(candidate(tmp_path))
    output = tmp_path / "benchmark.jsonl"
    lock = tmp_path / "lock.json"

    result = curator.export_benchmark([record], output, lock)

    assert result["status"] == "locked"
    assert result["locked_record_ids"] == [record["sample_id"]]
    exported = curator.load_manifest(output)
    assert exported[0]["subset"] == "independent_validation"


def test_export_marks_unreviewed_manifest_not_ready(tmp_path: Path) -> None:
    record = candidate(tmp_path)
    result = curator.export_benchmark([record], tmp_path / "benchmark.jsonl", tmp_path / "lock.json")

    assert result["status"] == "not_ready"
    assert result["headline_metrics_allowed"] is False
    assert result["rejected_records"]


def test_minimum_target_warning_is_deterministic() -> None:
    result = curator._shortfall([])

    assert result["minimum_shortfall"] == {"safe": 100, "suspicious": 50, "phishing": 100}
    assert result["recommended_shortfall"] == {"safe": 300, "suspicious": 100, "phishing": 300}
