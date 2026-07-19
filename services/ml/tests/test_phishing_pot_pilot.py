"""Synthetic-only tests for Phishing Pot pilot planning and reporting."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishshield_ml.phishing_pot_pilot import (
    PLANNED_COUNT,
    build_preflight_validation,
    build_source_inventory,
    derive_safe_eml_metadata,
    load_metadata_jsonl,
    scan_eml_directory,
    select_pilot_candidates,
    write_safe_metadata_jsonl,
    write_preflight_validation,
)
from phishshield_ml.phishing_pot_run import (
    _staged_metadata,
    update_pilot_review,
    write_blocked_promotion_preview,
)
from phishshield_ml.controlled_acquisition import PILOT_REVIEW_CLASSIFICATIONS


ROOT = Path(__file__).resolve().parents[1]


def _records(count: int = 30) -> list[dict]:
    return [
        {
            "candidate_id": f"synthetic-{index:02d}",
            "period_bucket": f"2025/{(index % 12) + 1:02d}",
            "language": "en",
            "mime_types": ["text/plain", "text/html; charset=utf-8"],
            "attachment_count": index % 2,
            "malformed": False,
            "parse_safe": True,
            "sha256": f"exact-{index:02d}",
            "normalized_hash": f"normalized-{index:02d}",
            "campaign_group": f"campaign-{index:02d}",
            "template_group": f"template-{index:02d}",
            "brand_group": f"brand-{index % 6}",
            "phishing_intent": True,
            "privacy_unresolved": False,
            "boundary_overlap": False,
            "boundary_overlap_status": "compared_clear",
            "internal_duplicate_status": "clear",
            "has_header_evidence": index % 2 == 0,
            "has_url_evidence": True,
            "has_authentication_evidence": index % 3 == 0,
        }
        for index in range(count)
    ]


def _review_queue(count: int = 2) -> dict:
    return {
        "schema_version": 1,
        "pilot_id": "phishing_pot_pilot_001",
        "source_id": "github_rf_peixoto_phishing_pot",
        "review_status": "awaiting_manual_review",
        "reviewed_count": 0,
        "allowed_classifications": sorted(PILOT_REVIEW_CLASSIFICATIONS),
        "samples": [
            {
                "candidate_id": f"candidate-{index:02d}",
                "classification": None,
                "phishing_confirmed": None,
                "privacy_checks_passed": None,
                "license_checks_passed": None,
                "grouping_reviewed": None,
                "duplicate_checks_passed": True,
                "overlap_checks_passed": True,
                "campaign_group": f"campaign-{index:02d}",
                "template_group": f"template-{index:02d}",
                "manual_approved": None,
                "reviewer": None,
                "reviewed_at": None,
                "safe_notes": None,
            }
            for index in range(count)
        ],
    }


def _write_review_queue(tmp_path: Path, count: int = 2) -> Path:
    path = tmp_path / "pilot_review_queue.json"
    path.write_text(json.dumps(_review_queue(count)), encoding="utf-8")
    return path


def test_preflight_passes_and_preserves_all_promotion_blocks(tmp_path: Path) -> None:
    report = build_preflight_validation(ROOT)
    assert report["passed"] is True
    assert report["planned_candidate_count"] == PLANNED_COUNT
    assert report["promotion_eligible"] is False
    assert {"development_use_disabled", "source_approval_incomplete", "manual_approval_missing"} <= set(
        report["promotion_blockers"]
    )
    written = write_preflight_validation(ROOT, tmp_path)
    assert written == report
    assert (tmp_path / "preflight_validation.json").is_file()
    assert "Promotion eligible: no" in (tmp_path / "preflight_validation.md").read_text(encoding="utf-8")


def test_inventory_is_aggregate_and_counts_duplicates_without_content() -> None:
    rows = _records(3)
    rows[1]["sha256"] = rows[0]["sha256"]
    rows[2]["normalized_hash"] = rows[0]["normalized_hash"]
    rows[2]["language"] = "unknown"
    rows[2]["malformed"] = True
    report = build_source_inventory(rows, source_commit_sha="0" * 40)
    assert report["total_eml_files"] == 3
    assert report["exact_duplicate_count"] == 1
    assert report["normalized_duplicate_count"] == 1
    assert report["malformed_message_count"] == 1
    assert report["language_distribution"] == {"en": 2, "unknown": 1}
    serialized = json.dumps(report)
    assert "message body" not in serialized.lower()
    assert "@" not in serialized


def test_selection_is_deterministic_exact_and_diverse() -> None:
    rows = _records()
    first = select_pilot_candidates(rows)
    second = select_pilot_candidates(reversed(rows))
    assert first == second
    assert first["selected_count"] == PLANNED_COUNT
    assert len(set(first["selected_candidate_ids"])) == PLANNED_COUNT
    assert max(first["campaign_distribution"].values()) <= 2
    assert max(first["template_distribution"].values()) == 1
    assert max(first["brand_distribution"].values()) <= 5
    assert first["all_candidates_provisional"] is True
    assert first["promotion_eligible"] is False


def test_selection_rejects_non_english_privacy_overlap_and_duplicates() -> None:
    rows = _records(26)
    rows[0]["language"] = "es"
    rows[1]["privacy_unresolved"] = True
    rows[2]["boundary_overlap"] = True
    rows[3]["normalized_hash"] = rows[4]["normalized_hash"]
    report = select_pilot_candidates(rows)
    assert report["selected_count"] == PLANNED_COUNT
    assert report["excluded_reason_counts"]["non_english"] == 1
    assert report["excluded_reason_counts"]["privacy_unresolved"] == 1
    assert report["excluded_reason_counts"]["boundary_overlap"] == 1
    assert report["excluded_reason_counts"]["duplicate"] == 1


def test_metadata_loader_rejects_message_content_and_sensitive_fields(tmp_path: Path) -> None:
    path = tmp_path / "metadata.jsonl"
    path.write_text(json.dumps({"candidate_id": "safe-1", "body": "must not enter planning reports"}), encoding="utf-8")
    with pytest.raises(ValueError, match="forbidden content fields"):
        load_metadata_jsonl(path)


def test_inventory_rejects_address_like_candidate_identifier() -> None:
    row = _records(1)[0]
    row["candidate_id"] = "person@example.test"
    with pytest.raises(ValueError, match="opaque privacy-safe identifier"):
        build_source_inventory([row])


def test_safe_eml_metadata_contains_only_opaque_or_aggregate_evidence() -> None:
    raw = b"""From: Private Person <private.person@sensitive.example>
Reply-To: actor@unrelated.example
Subject: Urgent account verification
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Verify your password immediately.</p>
<a href="https://credential.example/login?token=do-not-persist">Sign in</a>
<img src="https://tracking.example/pixel?id=private">
"""
    row = derive_safe_eml_metadata(raw, relative_path=Path("2025/03/sample.eml"))
    serialized = json.dumps(row)
    assert row["candidate_id"].startswith("candidate-")
    assert row["language"] == "en"
    assert row["mime_types"] == ["text/html"]
    assert row["remote_resources_blocked"] == 1
    assert row["has_url_evidence"] is True
    assert row["phishing_intent"] is True
    assert row["boundary_overlap_status"] == "not_yet_compared"
    assert "private.person" not in serialized
    assert "sensitive.example" not in serialized
    assert "credential.example" not in serialized
    assert "tracking.example" not in serialized
    assert "do-not-persist" not in serialized
    assert "Verify your password" not in serialized
    assert not {"text", "body", "html", "urls", "from", "to", "reply_to"}.intersection(row)


def test_directory_scanner_streams_only_eml_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.eml").write_bytes(b"Subject: Account\nContent-Type: text/plain\n\nReview your account")
    (source / "ignored.txt").write_text("not an email fixture", encoding="utf-8")
    rows = list(scan_eml_directory(source))
    assert len(rows) == 1
    assert rows[0]["source_bytes"] > 0

    output = tmp_path / "derived" / "metadata.jsonl"
    summary = write_safe_metadata_jsonl(source, output)
    assert summary == {"scanned": 1, "parse_safe": 1, "unsafe": 0}
    loaded = load_metadata_jsonl(output)
    assert loaded[0]["candidate_id"] == rows[0]["candidate_id"]


def test_selection_blocks_scanner_rows_until_overlap_check_is_complete() -> None:
    rows = _records()
    rows[0]["boundary_overlap_status"] = "not_yet_compared"
    report = select_pilot_candidates(rows)
    assert report["selected_count"] == PLANNED_COUNT
    assert report["excluded_reason_counts"]["boundary_overlap_incomplete"] == 1


@pytest.mark.parametrize("classification", sorted(PILOT_REVIEW_CLASSIFICATIONS))
def test_update_pilot_review_accepts_only_closed_adjudication_enum(
    tmp_path: Path, classification: str,
) -> None:
    queue_path = _write_review_queue(tmp_path)
    result = update_pilot_review(
        queue_path, "candidate-00", classification, "synthetic-reviewer"
    )
    assert result["classification"] == classification
    assert json.loads(queue_path.read_text(encoding="utf-8"))["reviewed_count"] == 1

    with pytest.raises(ValueError, match="Unsupported pilot classification"):
        update_pilot_review(
            queue_path, "candidate-01", "repository_says_phishing", "synthetic-reviewer"
        )


@pytest.mark.parametrize(
    "unsafe_notes",
    [
        "Contact private.person@example.test",
        "Evidence at https://example.test/path?token=secret",
        "x" * 501,
    ],
)
def test_update_pilot_review_rejects_privacy_unsafe_notes(
    tmp_path: Path, unsafe_notes: str,
) -> None:
    queue_path = _write_review_queue(tmp_path)
    before = queue_path.read_bytes()
    with pytest.raises(ValueError, match="safe_notes"):
        update_pilot_review(
            queue_path,
            "candidate-00",
            "ambiguous",
            "synthetic-reviewer",
            safe_notes=unsafe_notes,
        )
    assert queue_path.read_bytes() == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"phishing_confirmed": False},
        {"privacy_checks_passed": False},
        {"license_checks_passed": False},
        {"grouping_reviewed": False},
    ],
)
def test_phishing_manual_approval_requires_completed_checks(
    tmp_path: Path, overrides: dict[str, bool],
) -> None:
    queue_path = _write_review_queue(tmp_path)
    checks = {
        "phishing_confirmed": True,
        "privacy_checks_passed": True,
        "license_checks_passed": True,
        "grouping_reviewed": True,
        "manual_approved": True,
    }
    checks.update(overrides)
    with pytest.raises(ValueError, match="Phishing approval requires"):
        update_pilot_review(
            queue_path,
            "candidate-00",
            "phishing",
            "synthetic-reviewer",
            **checks,
        )


def test_phishing_manual_approval_requires_duplicate_and_overlap_clearance(
    tmp_path: Path,
) -> None:
    for failed_field in ("duplicate_checks_passed", "overlap_checks_passed"):
        queue = _review_queue()
        queue["samples"][0][failed_field] = False
        queue_path = tmp_path / f"{failed_field}.json"
        queue_path.write_text(json.dumps(queue), encoding="utf-8")
        with pytest.raises(ValueError, match="Phishing approval requires"):
            update_pilot_review(
                queue_path,
                "candidate-00",
                "phishing",
                "synthetic-reviewer",
                phishing_confirmed=True,
                privacy_checks_passed=True,
                license_checks_passed=True,
                grouping_reviewed=True,
                manual_approved=True,
            )


def test_blocked_preview_reports_initial_review_and_source_gates(tmp_path: Path) -> None:
    queue_path = _write_review_queue(tmp_path, count=22)
    output = tmp_path / "blocked_promotion_preview.json"
    before = queue_path.read_bytes()
    report = write_blocked_promotion_preview(ROOT, queue_path, output)
    assert report["result"] == "blocked_as_expected"
    assert report["promotion_eligible"] is False
    assert report["candidate_count"] == 22
    assert report["files_copied"] == 0
    assert {
        "development_use_disabled",
        "source_approval_incomplete",
        "source_privacy_review_incomplete",
        "source_ingestion_disabled",
        "manual_adjudication_incomplete",
        "sample_privacy_review_incomplete",
        "sample_license_review_incomplete",
        "campaign_template_review_incomplete",
        "reviewer_approval_missing",
    } <= set(report["blockers"])
    assert queue_path.read_bytes() == before
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_current_pilot_metadata_is_skipped_on_idempotent_overlap_rerun(
    tmp_path: Path,
) -> None:
    current = tmp_path / "data/staging/phishing_pot_pilot_001/validation/current.jsonl"
    current.parent.mkdir(parents=True)
    current.write_text('{"body":"must never be loaded"}\n', encoding="utf-8")
    second_current_path = tmp_path / "metadata/current_scan.jsonl"
    second_current_path.parent.mkdir(parents=True)
    second_current_path.write_text("", encoding="utf-8")
    assert _staged_metadata(tmp_path, second_current_path) == []
