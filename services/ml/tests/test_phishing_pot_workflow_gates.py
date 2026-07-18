"""Regression coverage for the pending phishing-pot source workflow gates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishshield_ml.controlled_acquisition import (
    load_controlled_registry,
    validate_source_for_ingestion,
    validate_source_for_staging_plan,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ID = "github_rf_peixoto_phishing_pot"


def _source() -> dict:
    _, sources = load_controlled_registry(ROOT / "config/dataset_source_registry.json")
    return sources[SOURCE_ID]


def test_phishing_pot_registry_records_rights_and_capability_gates() -> None:
    source = _source()
    assert source["homepage"] == "https://github.com/rf-peixoto/phishing_pot"
    assert source["license_evidence_reference"].endswith("/blob/main/LICENSE")
    assert source["allowed_labels"] == [1]
    assert source["allowed_languages"] == ["en"]
    assert source["license_status"] == "verified_restricted_noncommercial"
    assert source["privacy_status"] == "pending_sample_review"
    assert source["approval_status"] == "pending"
    assert source["ingestion_enabled"] is False
    assert source["development_allowed"] is False
    assert source["redistribution_allowed"] is False


def test_pending_source_can_only_enter_noncommercial_staging() -> None:
    source = _source()
    validate_source_for_staging_plan(source, "noncommercial_research")
    with pytest.raises(PermissionError, match="non-commercial research"):
        validate_source_for_staging_plan(source, "commercial")
    with pytest.raises(PermissionError, match="development use is disabled"):
        validate_source_for_ingestion(source, "development_pool", "eml")


def test_pending_source_cannot_become_ingestion_enabled_by_metadata_only(tmp_path: Path) -> None:
    payload = json.loads((ROOT / "config/dataset_source_registry.json").read_text(encoding="utf-8"))
    source = next(item for item in payload["sources"] if item["source_id"] == SOURCE_ID)
    source["ingestion_enabled"] = True
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="not fully approved"):
        load_controlled_registry(registry_path)


def test_source_review_packet_is_metadata_only_and_covers_required_risks() -> None:
    packet = (ROOT / "config/report_templates/phishing_pot_pilot/source_review_packet.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "cc by-nc", "non-commercial", "third-party", "url query", "encoded content",
        "attachments", "spam", "language", "campaign", "template", "no source may be cloned",
    ):
        assert phrase in packet
    assert "contains no cloned repository content" in packet


def test_batch_001_keeps_phishing_pot_as_source_a_candidate() -> None:
    plan = json.loads((ROOT / "config/acquisition_batches/batch_001.json").read_text(encoding="utf-8"))
    row = next(item for item in plan["source_distribution"] if item.get("source_id") == SOURCE_ID)
    assert row["source_slot"] == "pending_phishing_source_a"
    assert 20 <= row["planned_count"] <= 25
    assert row["approval_state_snapshot"] == "pending"
    assert plan["readiness_expectation"] == "blocked_pending_source_approval"
