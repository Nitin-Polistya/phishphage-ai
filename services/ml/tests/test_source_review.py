from __future__ import annotations

import copy
import json

from phishshield_ml.source_review import audit_registry_payload, validate_batch_plan


TAXONOMY = {
    "legit_account_notification": 0,
    "phish_credential_theft": 1,
    "phish_banking": 1,
}


def _source(source_id: str, label: int, **overrides: object) -> dict:
    category = "legit_account_notification" if label == 0 else "phish_credential_theft"
    source = {
        "source_id": source_id, "display_name": source_id, "homepage": f"https://example.invalid/{source_id}",
        "dataset_reference": f"reference:{source_id}", "license": "Reviewed fixture license",
        "license_status": "approved", "privacy_status": "approved", "approval_status": "approved",
        "allowed_languages": ["en"], "allowed_labels": [label], "allowed_splits": ["development_pool"],
        "redistribution_allowed": False, "external_only": False, "ingestion_enabled": True,
        "approval_notes": "fixture", "approved_by": "reviewer", "approved_date": "2026-07-18",
        "required_fields": ["text", "label"], "deduplication_policy": "reject",
        "campaign_policy": "one split", "supported_formats": ["jsonl"],
        "permitted_categories": [category], "raw_storage_allowed": True, "required_redactions": [],
        "acquisition_method": {"type": "fixture", "reference": "fixture", "status": "approved"},
        "license_evidence_reference": "license-evidence", "license_evidence_checked_at": "2026-07-18",
        "privacy_evidence_reference": "privacy-evidence", "privacy_evidence_checked_at": "2026-07-18",
        "acquisition_evidence_reference": "acquisition-evidence", "reviewer": "reviewer",
        "review_notes": "fixture", "unresolved_questions": [],
    }
    source.update(overrides)
    return source


def _registry(sources: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "status_enums": ["approved", "blocked", "pending", "external_only"],
        "policy": {}, "sources": sources,
    }


def _plan(sources: list[dict], total: int = 100) -> dict:
    counts = [34, 33, 33][:len(sources)]
    if len(sources) == 1:
        counts = [total]
    distributions = [{
        "source_slot": source["source_id"], "source_id": source["source_id"],
        "independent_source_family": source["source_id"], "planned_count": counts[index],
        "configured_limit_percent": 100 if len(sources) == 1 else 35, "is_synthetic": False,
    } for index, source in enumerate(sources)]
    allocations = []
    for index, source in enumerate(sources):
        category = source["permitted_categories"][0]
        allocations.append({
            "category": category, "label": source["allowed_labels"][0], "target_count": counts[index],
            "minimum_campaign_groups": 2, "minimum_templates": max(7, counts[index] // 5 + 1),
            "minimum_organizations_or_brands": 2, "source_registry_id": source["source_id"],
            "intended_use": "development_pool",
        })
    return {
        "batch_id": "fixture", "target_range": {"minimum": 100, "maximum": 150},
        "planned_total": total, "synthetic_rows_planned": 0,
        "maximum_source_contribution_percent": 100 if len(sources) == 1 else 35,
        "maximum_template_contribution_percent": 5,
        "dominant_existing_source": {"source_id": "dominant", "maximum_contribution_percent": 20},
        "minimum_approved_independent_sources": 2,
        "source_distribution": distributions, "allocations": allocations,
    }


def test_conflicting_registry_metadata_is_reported() -> None:
    source = _source(
        "external-conflict", 1, external_only=True, approval_status="approved",
        allowed_splits=["development_pool"], ingestion_enabled=True,
    )
    audit = audit_registry_payload(_registry([source]), TAXONOMY)
    issues = audit["sources"][0]["issues"]
    assert "external_only_approval_conflict" in issues
    assert "external_only_ingestion_enabled" in issues


def test_missing_evidence_references_are_reported() -> None:
    source = _source("missing-evidence", 0, license_evidence_reference=None, privacy_evidence_reference=None)
    audit = audit_registry_payload(_registry([source]), TAXONOMY)
    issues = audit["sources"][0]["issues"]
    assert "approved_license_missing_evidence" in issues
    assert "approved_privacy_missing_evidence" in issues


def test_fewer_than_two_approved_sources_and_single_source_are_blocked() -> None:
    source = _source("only-source", 0)
    report = validate_batch_plan(_plan([source]), _registry([source]), TAXONOMY)
    assert report["conclusion"] == "blocked_pending_source_approval"
    assert any("fewer_than_two_approved_independent_sources" in item for item in report["approval_blockers"])


def test_blocked_source_in_plan_is_blocked() -> None:
    sources = [_source("blocked-source", 0, approval_status="blocked", ingestion_enabled=False), _source("approved-two", 1), _source("approved-three", 1)]
    report = validate_batch_plan(_plan(sources), _registry(sources), TAXONOMY)
    assert report["conclusion"] == "blocked_pending_source_approval"
    assert "blocked_source_scheduled:blocked-source" in report["approval_blockers"]


def test_pending_source_in_plan_is_blocked() -> None:
    sources = [_source("pending-source", 0, approval_status="pending", ingestion_enabled=False), _source("approved-two", 1), _source("approved-three", 1)]
    report = validate_batch_plan(_plan(sources), _registry(sources), TAXONOMY)
    assert "pending_source_scheduled:pending-source" in report["approval_blockers"]


def test_dominant_source_above_twenty_percent_is_invalid() -> None:
    sources = [_source("dominant", 0), _source("source-two", 1), _source("source-three", 1)]
    report = validate_batch_plan(_plan(sources), _registry(sources), TAXONOMY)
    assert report["conclusion"] == "invalid_batch_plan"
    assert any("dominant_source_above_20_percent" in item for item in report["errors"])


def test_synthetic_allocation_is_invalid() -> None:
    sources = [_source("source-one", 0), _source("source-two", 1), _source("source-three", 1)]
    plan = _plan(sources)
    plan["source_distribution"][0]["is_synthetic"] = True
    report = validate_batch_plan(plan, _registry(sources), TAXONOMY)
    assert "synthetic_allocation_prohibited" in report["errors"]


def test_external_only_development_source_is_invalid() -> None:
    sources = [
        _source("external-source", 0, approval_status="external_only", external_only=True, ingestion_enabled=False, allowed_splits=["external"]),
        _source("source-two", 1), _source("source-three", 1),
    ]
    report = validate_batch_plan(_plan(sources), _registry(sources), TAXONOMY)
    assert "external_only_source_scheduled_for_development:external-source" in report["errors"]


def test_valid_diverse_batch_is_ready() -> None:
    sources = [_source("source-one", 0), _source("source-two", 1), _source("source-three", 1)]
    report = validate_batch_plan(_plan(sources), _registry(sources), TAXONOMY)
    assert report["conclusion"] == "ready_for_acquisition"
    assert report["errors"] == []
    assert report["approval_blockers"] == []


def test_readiness_report_is_deterministic() -> None:
    sources = [_source("source-one", 0), _source("source-two", 1), _source("source-three", 1)]
    plan = _plan(sources)
    first = validate_batch_plan(copy.deepcopy(plan), copy.deepcopy(_registry(sources)), TAXONOMY)
    second = validate_batch_plan(copy.deepcopy(plan), copy.deepcopy(_registry(sources)), TAXONOMY)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
