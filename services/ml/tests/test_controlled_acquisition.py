from __future__ import annotations

import json
import shutil
from pathlib import Path

import pandas as pd
import pytest

from phishshield_ml.controlled_acquisition import (
    PILOT_REVIEW_CLASSIFICATIONS,
    ingest_batch,
    initialize_batch,
    load_controlled_registry,
    pilot_promotion_eligibility,
    promote_batch,
    update_review,
    validate_source_for_ingestion,
    validate_source_for_staging_plan,
)


ML_ROOT = Path(__file__).resolve().parents[1]


def _source(**overrides: object) -> dict:
    source = {
        "source_id": "approved-source", "display_name": "Approved Fixture Source",
        "homepage": "https://example.invalid/dataset", "dataset_reference": "fixture-reference",
        "license": "Fixture license reviewed for tests", "license_status": "approved",
        "privacy_status": "approved", "approval_status": "approved", "allowed_languages": ["en"],
        "allowed_labels": [0, 1], "allowed_splits": ["development_pool"],
        "redistribution_allowed": False, "external_only": False, "ingestion_enabled": True,
        "staging_allowed": True, "development_allowed": True,
        "approval_notes": "Test fixture only", "approved_by": "test-reviewer", "approved_date": "2026-07-18",
        "required_fields": ["text", "label", "language", "source_record_id", "campaign_group", "template_group", "message_type", "is_synthetic"],
        "deduplication_policy": "reject duplicates", "campaign_policy": "one split only",
        "supported_formats": ["jsonl", "csv"],
        "permitted_categories": ["legit_workplace_collaboration", "phish_credential_theft"],
        "raw_storage_allowed": True, "required_redactions": [],
        "acquisition_method": {"type": "test_fixture", "reference": "fixture", "status": "approved"},
        "license_evidence_reference": "fixture-license", "license_evidence_checked_at": "2026-07-18",
        "privacy_evidence_reference": "fixture-privacy", "privacy_evidence_checked_at": "2026-07-18",
        "acquisition_evidence_reference": "fixture-acquisition", "reviewer": "test-reviewer",
        "review_notes": "fixture", "unresolved_questions": [],
    }
    source.update(overrides)
    return source


def _setup_root(tmp_path: Path, source: dict | None = None) -> Path:
    (tmp_path / "config").mkdir()
    shutil.copyfile(
        ML_ROOT / "config/dataset_expansion_taxonomy.json",
        tmp_path / "config/dataset_expansion_taxonomy.json",
    )
    registry = {
        "schema_version": 1,
        "status_enums": ["approved", "blocked", "pending", "external_only"],
        "policy": {"direct_development_ingestion": False},
        "sources": [source or _source()],
    }
    (tmp_path / "config/dataset_source_registry.json").write_text(json.dumps(registry), encoding="utf-8")
    return tmp_path


def _row(text: str = "Routine project planning note for tomorrow", **overrides: object) -> dict:
    row = {
        "text": text, "label": 0, "language": "en", "source_record_id": "record-1",
        "campaign_group": "campaign-new", "template_group": "template-new",
        "message_type": "legit_workplace_collaboration", "is_synthetic": False,
    }
    row.update(overrides)
    return row


def _create_batch(root: Path, batch_id: str, rows: list[dict], source_id: str = "approved-source") -> Path:
    directory = initialize_batch(root, batch_id, source_id, "source.jsonl")
    with (directory / "raw/source.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return directory


def test_repository_registry_is_valid() -> None:
    payload, sources = load_controlled_registry(ML_ROOT / "config/dataset_source_registry.json")
    assert payload["policy"]["direct_development_ingestion"] is False
    assert sources["zenodo_phishing_validation_13474746"]["external_only"] is True


def test_pending_phishing_pot_cannot_be_ingested() -> None:
    _, sources = load_controlled_registry(ML_ROOT / "config/dataset_source_registry.json")
    source = sources["github_rf_peixoto_phishing_pot"]
    assert source["approval_status"] == "pending"
    assert source["ingestion_enabled"] is False
    assert source["staging_allowed"] is True
    assert source["development_allowed"] is False
    assert source["license_status"] == "verified_restricted_noncommercial"
    assert source["privacy_status"] == "pending_sample_review"
    validate_source_for_staging_plan(source, "noncommercial_research")
    with pytest.raises(PermissionError, match="development use is disabled"):
        validate_source_for_ingestion(source, "development_pool", "eml")


def test_restricted_source_staging_rejects_commercial_use() -> None:
    _, sources = load_controlled_registry(ML_ROOT / "config/dataset_source_registry.json")
    source = sources["github_rf_peixoto_phishing_pot"]
    with pytest.raises(PermissionError, match="restricted to non-commercial research"):
        validate_source_for_staging_plan(source, "commercial")


def _pilot_review(**overrides: object) -> dict:
    review = {
        "classification": "phishing", "manual_approved": True,
        "phishing_confirmed": True, "language": "en", "privacy_checks_passed": True,
        "duplicate_checks_passed": True, "overlap_checks_passed": True,
        "campaign_group": "campaign-1", "template_group": "template-1",
    }
    review.update(overrides)
    return review


def test_pilot_adjudication_enum_is_complete_and_closed() -> None:
    assert PILOT_REVIEW_CLASSIFICATIONS == {
        "phishing",
        "spam_not_phishing",
        "scam_not_phishing",
        "malware_not_phishing",
        "ambiguous",
        "reject_privacy",
        "reject_duplicate",
        "reject_non_english",
        "reject_corrupt",
    }


@pytest.mark.parametrize(
    "classification",
    sorted(PILOT_REVIEW_CLASSIFICATIONS - {"phishing"}),
)
def test_non_phishing_or_rejected_pilot_classifications_cannot_promote(classification: str) -> None:
    source = _source()
    result = pilot_promotion_eligibility(source, _pilot_review(classification=classification))
    assert result["eligible"] is False
    assert f"classification_not_phishing:{classification}" in result["reasons"]


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("privacy_checks_passed", "sample_privacy_check_failed"),
        ("duplicate_checks_passed", "duplicate_check_failed"),
        ("overlap_checks_passed", "development_overlap_check_failed"),
    ],
)
def test_pilot_privacy_duplicate_and_overlap_failures_block_promotion(field: str, reason: str) -> None:
    result = pilot_promotion_eligibility(_source(), _pilot_review(**{field: False}))
    assert result["eligible"] is False
    assert reason in result["reasons"]


def test_pending_source_remains_ineligible_even_after_positive_sample_review() -> None:
    _, sources = load_controlled_registry(ML_ROOT / "config/dataset_source_registry.json")
    result = pilot_promotion_eligibility(
        sources["github_rf_peixoto_phishing_pot"], _pilot_review()
    )
    assert result["eligible"] is False
    assert "development_use_disabled" in result["reasons"]
    assert "source_approval_incomplete" in result["reasons"]
    assert "privacy_review_incomplete" in result["reasons"]


def test_development_disabled_source_cannot_promote_even_when_other_gates_pass() -> None:
    result = pilot_promotion_eligibility(
        _source(development_allowed=False), _pilot_review()
    )
    assert result == {"eligible": False, "reasons": ["development_use_disabled"]}


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("manual_approved", "manual_approval_missing"),
        ("phishing_confirmed", "phishing_behavior_not_confirmed"),
        ("language", "english_language_not_confirmed"),
        ("privacy_checks_passed", "sample_privacy_check_failed"),
        ("duplicate_checks_passed", "duplicate_check_failed"),
        ("overlap_checks_passed", "development_overlap_check_failed"),
        ("campaign_group", "campaign_group_missing"),
        ("template_group", "template_group_missing"),
    ],
)
def test_incomplete_sample_review_cannot_promote(field: str, reason: str) -> None:
    incomplete_value: object = (
        "es" if field == "language" else ("" if field.endswith("_group") else False)
    )
    result = pilot_promotion_eligibility(
        _source(), _pilot_review(**{field: incomplete_value})
    )
    assert result["eligible"] is False
    assert reason in result["reasons"]


def test_pilot_promotion_blockers_are_deterministic() -> None:
    source = _source(
        development_allowed=False,
        approval_status="pending",
        privacy_status="pending_sample_review",
    )
    review = _pilot_review(
        classification="reject_corrupt",
        manual_approved=False,
        phishing_confirmed=False,
        language="und",
        privacy_checks_passed=False,
        duplicate_checks_passed=False,
        overlap_checks_passed=False,
        campaign_group="",
        template_group="",
    )
    expected = [
        "development_use_disabled",
        "source_approval_incomplete",
        "privacy_review_incomplete",
        "manual_approval_missing",
        "classification_not_phishing:reject_corrupt",
        "phishing_behavior_not_confirmed",
        "english_language_not_confirmed",
        "sample_privacy_check_failed",
        "duplicate_check_failed",
        "development_overlap_check_failed",
        "campaign_group_missing",
        "template_group_missing",
    ]
    assert pilot_promotion_eligibility(source, review)["reasons"] == expected
    assert pilot_promotion_eligibility(source, review)["reasons"] == expected


def test_unknown_license_must_remain_pending(tmp_path: Path) -> None:
    root = _setup_root(tmp_path, _source(license="unknown", license_status="approved"))
    with pytest.raises(ValueError, match="Unknown license must remain pending"):
        load_controlled_registry(root / "config/dataset_source_registry.json")


def test_license_and_approval_rejection(tmp_path: Path) -> None:
    root = _setup_root(tmp_path, _source(license_status="blocked", approval_status="blocked", ingestion_enabled=False))
    _create_batch(root, "batch-blocked", [_row()])
    with pytest.raises(PermissionError, match="license is not approved"):
        ingest_batch(root, "batch-blocked")


def test_source_privacy_rejection(tmp_path: Path) -> None:
    root = _setup_root(tmp_path, _source(privacy_status="blocked", approval_status="blocked", ingestion_enabled=False))
    _create_batch(root, "batch-privacy-blocked", [_row()])
    with pytest.raises(PermissionError, match="privacy review is not approved"):
        ingest_batch(root, "batch-privacy-blocked")


def test_external_only_source_is_isolated(tmp_path: Path) -> None:
    source = _source(
        approval_status="external_only", external_only=True, ingestion_enabled=False,
        allowed_splits=["external"],
    )
    root = _setup_root(tmp_path, source)
    directory = initialize_batch(root, "batch-external", "approved-source", "source.jsonl", "external")
    (directory / "raw/source.jsonl").write_text(json.dumps(_row()) + "\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="external-only"):
        ingest_batch(root, "batch-external")


def test_privacy_issue_is_rejected_without_exporting_value(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    directory = _create_batch(root, "batch-private", [_row(recipient_email="person@example.com")])
    report = ingest_batch(root, "batch-private")
    rejected_text = (directory / "reports/rejected_rows.json").read_text(encoding="utf-8")
    assert report["accepted_rows"] == 0
    assert "privacy_forbidden_field:recipient_email" in rejected_text
    assert "person@example.com" not in rejected_text


def test_duplicate_detection_rejects_repeated_rows(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    second = _row(source_record_id="record-2", campaign_group="campaign-2", template_group="template-2")
    directory = _create_batch(root, "batch-duplicate", [_row(), second])
    report = ingest_batch(root, "batch-duplicate")
    duplicate_report = json.loads((directory / "reports/duplicate_report.json").read_text(encoding="utf-8"))
    assert report["accepted_rows"] == 1
    assert report["rejected_rows"] == 1
    assert any(match["reason"] == "batch_duplicate" for match in duplicate_report[0]["matches"])


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"language": "es"}, "unsupported_language"),
        ({"message_type": "not_in_taxonomy"}, "missing_taxonomy"),
        ({"campaign_group": ""}, "missing_provenance:campaign_group"),
    ],
)
def test_unsupported_and_incomplete_rows_are_rejected(
    tmp_path: Path, overrides: dict[str, object], reason: str,
) -> None:
    root = _setup_root(tmp_path)
    directory = _create_batch(root, "batch-invalid", [_row(**overrides)])
    report = ingest_batch(root, "batch-invalid")
    assert report["accepted_rows"] == 0
    assert reason in (directory / "reports/rejected_rows.json").read_text(encoding="utf-8")


def test_generic_spam_cannot_be_relabelled_as_phishing(tmp_path: Path) -> None:
    source = _source(source_id="apache_spamassassin_spam", allowed_labels=[1])
    root = _setup_root(tmp_path, source)
    row = _row(
        label=1, message_type="phish_credential_theft", source_record_id="spam-1",
    )
    directory = _create_batch(root, "batch-spam", [row], source_id="apache_spamassassin_spam")
    report = ingest_batch(root, "batch-spam")
    assert report["accepted_rows"] == 0
    assert "spam_relabelled_as_phishing" in (directory / "reports/rejected_rows.json").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [("campaign_group", "existing-campaign", "campaign_overlap"), ("template_group", "existing-template", "template_overlap")],
)
def test_development_group_overlap_is_rejected(tmp_path: Path, field: str, value: str, reason: str) -> None:
    root = _setup_root(tmp_path)
    processed = root / "data/processed"
    processed.mkdir(parents=True)
    pd.DataFrame([_row("An existing development message", campaign_group="existing-campaign", template_group="existing-template")]).to_csv(
        processed / "english_core_v3.csv", index=False,
    )
    candidate = _row("A distinct proposed message with unrelated wording", **{field: value})
    directory = _create_batch(root, f"batch-{field}", [candidate])
    report = ingest_batch(root, f"batch-{field}")
    assert report["accepted_rows"] == 0
    assert reason in (directory / "reports/rejected_rows.json").read_text(encoding="utf-8")


def test_external_benchmark_overlap_is_rejected(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    external = root / "data/external"
    external.mkdir(parents=True)
    row = _row("Unique external benchmark control message")
    pd.DataFrame([row]).to_csv(external / "final_external_benchmark.csv", index=False)
    directory = _create_batch(root, "batch-external-overlap", [row])
    report = ingest_batch(root, "batch-external-overlap")
    assert report["accepted_rows"] == 0
    assert "external_benchmark_overlap" in (directory / "reports/rejected_rows.json").read_text(encoding="utf-8")


def test_manual_approval_requires_privacy_and_license_checks(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    _create_batch(root, "batch-review", [_row()])
    ingest_batch(root, "batch-review")
    sample_id = json.loads((root / "data/staging/batch-review/validation/review_queue.jsonl").read_text(encoding="utf-8"))["sample_id"]
    with pytest.raises(ValueError, match="privacy_checked and license_checked"):
        update_review(root, "batch-review", sample_id, "approve", "reviewer")


def test_dry_run_does_not_promote_unapproved_rows(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    _create_batch(root, "batch-dry-run", [_row()])
    ingest_batch(root, "batch-dry-run")
    destination = root / "data/processed/promoted.csv"
    preview = promote_batch(root, "batch-dry-run", destination, confirm=False)
    assert preview["promotion_performed"] is False
    assert preview["blockers"]
    assert {"class_balance", "source_balance", "campaign_balance", "taxonomy_balance", "synthetic_percentage", "new_campaigns"} <= set(preview)
    assert not destination.exists()
    with pytest.raises(PermissionError, match="Promotion blocked"):
        promote_batch(root, "batch-dry-run", destination, confirm=True)


def test_confirmed_promotion_requires_and_uses_full_approval(tmp_path: Path) -> None:
    root = _setup_root(tmp_path)
    directory = _create_batch(root, "batch-promote", [_row()])
    ingest_batch(root, "batch-promote")
    review = json.loads((directory / "validation/review_queue.jsonl").read_text(encoding="utf-8"))
    update_review(
        root, "batch-promote", review["sample_id"], "approve", "reviewer",
        privacy_checked=True, license_checked=True,
    )
    destination = root / "data/processed/promoted.csv"
    preview = promote_batch(root, "batch-promote", destination, confirm=False)
    assert preview["approved_rows"] == 1
    assert preview["promotion_performed"] is False
    assert not destination.exists()
    receipt = promote_batch(root, "batch-promote", destination, confirm=True)
    assert receipt["promotion_performed"] is True
    assert len(pd.read_csv(destination)) == 1
    assert (directory / "reports/promotion_receipt.json").exists()
