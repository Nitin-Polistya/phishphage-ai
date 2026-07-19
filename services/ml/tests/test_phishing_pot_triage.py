"""Synthetic-only safety tests for the Phishing Pot triage workflow."""

from __future__ import annotations

import json
from pathlib import Path

from phishshield_ml.phishing_pot_triage import (
    TRIAGE_AUDIT_SEED,
    build_review_shortlist,
    triage_candidate,
)
from phishshield_ml.phishing_pot_run import write_blocked_promotion_preview


ROOT = Path(__file__).resolve().parents[1]


def _metadata(candidate_id: str = "candidate-synthetic-00", **overrides: object) -> dict:
    row = {
        "candidate_id": candidate_id,
        "language": "en",
        "language_confidence": 0.99,
        "parse_safe": True,
        "malformed": False,
        "parse_warning_categories": [],
        "attachment_count": 0,
        "privacy_flags": [],
        "privacy_unresolved": False,
        "privacy_review_required": False,
        "internal_duplicate_status": "clear",
        "boundary_overlap": False,
        "boundary_overlap_status": "compared_clear",
        "campaign_group": f"campaign-{candidate_id[-2:]}",
        "template_group": f"template-{candidate_id[-2:]}",
        "brand_group": "brand-alpha",
        "theme_group": "account_security",
    }
    row.update(overrides)
    return row


def _triage(evidence: dict[str, bool], **metadata: object) -> dict:
    return triage_candidate(_metadata(**metadata), evidence)


def _result(index: int, *, outcome: str = "high_confidence_phishing", family: str = "credential_theft", brand: str = "brand-alpha", contradictory: list[str] | None = None, privacy: bool = False) -> dict:
    return {
        "candidate_id": f"candidate-synthetic-{index:02d}",
        "provisional_outcome": outcome,
        "triage_score": 80 if outcome == "high_confidence_phishing" else 50,
        "supporting_evidence_categories": ["credential_request", "deceptive_destination"],
        "contradictory_evidence": contradictory or [],
        "confidence": 0.9,
        "reason": "Synthetic privacy-safe test result.",
        "required_next_action": "manual_review" if outcome != "high_confidence_phishing" else "spot_audit_if_selected",
        "phishing_family": family,
        "brand_bucket": brand,
        "campaign_group": f"campaign-{index:02d}",
        "template_group": f"template-{index:02d}",
        "privacy_review_required": privacy,
        "promotion_eligible": False,
        "reviewer_decision": None,
    }


def test_high_confidence_requires_two_independent_phishing_categories() -> None:
    result = _triage({"credential_request": True, "deceptive_destination": True})
    assert result["provisional_outcome"] == "high_confidence_phishing"
    assert {"credential_request", "deceptive_destination"} <= set(
        result["supporting_evidence_categories"]
    )
    assert result["promotion_eligible"] is False


def test_semantically_related_signals_count_as_one_evidence_group() -> None:
    for evidence in (
        {"credential_request": True, "login_verification_request": True},
        {"payment_redirection": True, "bec_indicator": True},
    ):
        result = _triage(evidence)
        assert result["provisional_outcome"] != "high_confidence_phishing"


def test_single_signal_and_brand_only_cannot_be_high_confidence() -> None:
    for evidence in ({"generic_urgency": True}, {"brand_impersonation": True}, {"suspicious_url": True}):
        result = _triage(evidence)
        assert result["provisional_outcome"] != "high_confidence_phishing"


def test_privacy_block_and_attachment_only_prevent_high_confidence() -> None:
    corroborated = {"credential_request": True, "deceptive_destination": True}
    privacy = _triage(
        corroborated,
        privacy_unresolved=True,
        privacy_review_required=True,
        privacy_flags=["sensitive_url_parameters_require_review"],
    )
    assert privacy["provisional_outcome"] == "reject_privacy"

    attachment = _triage(
        {**corroborated, "attachment_only": True},
        attachment_count=1,
    )
    assert attachment["provisional_outcome"] != "high_confidence_phishing"


def test_header_address_is_observational_but_decoded_address_requires_review() -> None:
    corroborated = {"credential_request": True, "deceptive_destination": True}
    header_only = _triage(
        corroborated,
        privacy_review_required=True,
        privacy_flags=["address_in_header"],
    )
    assert header_only["provisional_outcome"] == "high_confidence_phishing"
    assert header_only["privacy_review_required"] is False

    decoded_content = _triage(
        corroborated,
        privacy_review_required=True,
        privacy_flags=["address_in_header", "address_in_decoded_content"],
    )
    assert decoded_content["provisional_outcome"] == "reject_privacy"
    assert decoded_content["privacy_review_required"] is True


def test_shortlist_and_random_audit_are_deterministic() -> None:
    rows = [_result(index, family=f"family-{index % 2}", brand=f"brand-{index % 2}") for index in range(10)]
    first = build_review_shortlist(rows, seed=TRIAGE_AUDIT_SEED, audit_rate=0.20)
    second = build_review_shortlist(reversed(rows), seed=TRIAGE_AUDIT_SEED, audit_rate=0.20)
    assert first == second
    assert first["audit_seed"] == TRIAGE_AUDIT_SEED
    assert len(first["spot_audit_candidate_ids"]) == 2


def test_shortlist_covers_medium_privacy_contradictions_families_and_brands() -> None:
    rows = [
        _result(0, outcome="medium_confidence_review_required", family="credential_theft", brand="brand-alpha"),
        _result(1, family="invoice_fraud", brand="brand-beta", contradictory=["legitimate_context_signal"]),
        _result(2, family="qr_phishing", brand="brand-gamma", privacy=True),
        _result(3, family="credential_theft", brand="brand-alpha"),
        _result(4, family="invoice_fraud", brand="brand-beta"),
    ]
    shortlist = build_review_shortlist(rows, seed="synthetic-review-seed", audit_rate=0.20)
    selected = set(shortlist["candidate_ids"])
    assert {"candidate-synthetic-00", "candidate-synthetic-01", "candidate-synthetic-02"} <= selected
    selected_rows = shortlist["candidates"]
    for row in selected_rows:
        assert {
            "candidate_id", "provisional_outcome", "confidence",
            "evidence_categories", "manual_review_reasons", "phishing_family",
            "brand_bucket", "campaign_group", "template_group", "review_command",
        } <= set(row)
        command = row["review_command"]
        assert f"--candidate-id {row['candidate_id']}" in command
        assert "--privacy-checks-passed" in command
        assert "--license-checks-passed" in command
        assert "--grouping-reviewed" in command
    assert {row["phishing_family"] for row in selected_rows} >= {"credential_theft", "invoice_fraud", "qr_phishing"}
    assert {row["brand_bucket"] for row in selected_rows} >= {"brand-alpha", "brand-beta", "brand-gamma"}


def test_major_brand_coverage_excludes_unknown_bucket() -> None:
    rows = [
        _result(index, family="credential_theft", brand="brand-alpha")
        for index in range(3)
    ]
    rows.extend(
        _result(index, family="invoice_fraud", brand="brand-beta")
        for index in range(3, 5)
    )
    rows.extend(
        _result(index, family="other", brand="brand-unknown")
        for index in range(5, 8)
    )
    shortlist = build_review_shortlist(rows, seed="synthetic-brand-seed", audit_rate=0.20)
    selected_brands = {row["brand_bucket"] for row in shortlist["candidates"]}
    assert {"brand-alpha", "brand-beta"} <= selected_brands
    assert "brand-unknown" not in shortlist.get("major_brand_buckets", [])


def test_triage_never_fabricates_decisions_or_enables_training() -> None:
    config = json.loads(
        (ROOT / "config/acquisition_batches/phishing_pot_pilot_001.json").read_text(encoding="utf-8")
    )
    result = _triage({"credential_request": True, "deceptive_destination": True})
    assert config["automated_triage_allowed_for_training"] is False
    assert result["reviewer_decision"] is None
    assert result["promotion_eligible"] is False


def test_triage_result_does_not_copy_content_or_sensitive_value_fields() -> None:
    result = _triage(
        {"credential_request": True, "deceptive_destination": True},
        body="SENSITIVE_SENTINEL_BODY",
        urls=["SENSITIVE_SENTINEL_URL"],
        sender="SENSITIVE_SENTINEL_SENDER",
    )
    serialized = json.dumps(result)
    assert "SENSITIVE_SENTINEL" not in serialized
    assert not {"body", "text", "html", "urls", "sender", "reply_to"}.intersection(result)


def test_promotion_remains_blocked_after_automated_triage(tmp_path: Path) -> None:
    queue = {
        "samples": [
            {
                "candidate_id": "candidate-synthetic-00",
                "classification": None,
                "manual_approved": None,
                "privacy_checks_passed": None,
                "license_checks_passed": None,
                "grouping_reviewed": None,
            }
        ]
    }
    queue_path = tmp_path / "pilot_review_queue.json"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    before = queue_path.read_bytes()
    report = write_blocked_promotion_preview(ROOT, queue_path, tmp_path / "blocked.json")
    assert report["result"] == "blocked_as_expected"
    assert report["promotion_eligible"] is False
    assert report["files_copied"] == 0
    assert queue_path.read_bytes() == before
