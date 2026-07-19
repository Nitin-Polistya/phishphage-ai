from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from phishshield_ml.dataset import LABEL_QUALITIES, load_and_validate_dataset, validate_dataset_boundaries
from phishshield_ml.phishing_pot_weak_labels import (
    LABEL_QUALITIES as POLICY_LABEL_QUALITIES,
    WeakSamplingPolicy,
    build_derived_record,
    sample_campaign_balanced,
    sanitize_visible_text,
    weak_label_eligibility,
)
from phishshield_ml.training import fit_with_source_weights


def _metadata(**overrides):
    row = {
        "candidate_id": "candidate-synthetic", "language": "en", "language_confidence": .99,
        "parse_safe": True, "malformed": False, "privacy_unresolved": False,
        "internal_duplicate_status": "clear", "boundary_overlap": False,
        "campaign_group": "campaign-1", "template_group": "template-1",
        "brand_group": "brand-unknown",
    }
    row.update(overrides)
    return row


def _parsed(**overrides):
    row = {
        "subject": "Account notice", "plain_body": "Verify your account using the portal.",
        "sanitized_html_text": "", "sender_domain": "sender.example",
        "reply_to_domain": "sender.example", "urls": [], "authentication_headers": {},
        "mime_types": ["text/plain"], "attachments": [],
    }
    row.update(overrides)
    return row


def _evidence(**overrides):
    row = {"credential_request": True, "deceptive_destination": True}
    row.update(overrides)
    return row


def _triage(**overrides):
    row = {
        "provisional_outcome": "high_confidence_phishing",
        "independent_evidence_groups": ["credential_access_request", "destination_deception"],
        "supporting_evidence_categories": ["credential_request", "deceptive_destination"],
    }
    row.update(overrides)
    return row


def _sample(sample_id: str, campaign: str, template: str, brand: str = "brand-unknown") -> dict:
    return {"sample_id": sample_id, "campaign_group": campaign, "template_group": template, "brand_group": brand}


def test_label_quality_taxonomy_is_explicit_and_shared():
    expected = {"gold_manual", "silver_multi_source", "weak_source_provenance", "synthetic", "unknown"}
    assert set(POLICY_LABEL_QUALITIES) == expected
    assert LABEL_QUALITIES == expected


@pytest.mark.parametrize("partition", ["validation", "test", "diagnostic", "calibration", "threshold_selection", "external_evaluation", "benchmark"])
def test_weak_rows_are_blocked_from_non_training_boundaries(partition):
    frame = pd.DataFrame([{
        "label": 1, "label_quality": "weak_source_provenance", "split_role": "train_only",
        "review_status": "not_manually_reviewed", "privacy_status": "privacy_sanitized",
    }])
    with pytest.raises(ValueError, match="forbidden"):
        validate_dataset_boundaries(frame, partition=partition)


def test_weak_row_requires_train_only_role():
    frame = pd.DataFrame([{
        "label": 1, "label_quality": "weak_source_provenance", "split_role": "validation",
        "review_status": "not_manually_reviewed", "privacy_status": "privacy_sanitized",
    }])
    with pytest.raises(ValueError, match="train_only"):
        validate_dataset_boundaries(frame)


def test_deterministic_address_phone_token_account_and_url_redaction():
    raw = "Dear Alice Smith, email alice@example.test or phishing@pot or +1 202-555-0184. subscription ID XAS66762UK674 token=secret-value https://example.test/a?q=private#track"
    first = sanitize_visible_text(raw)
    second = sanitize_visible_text(raw)
    assert first == second
    sanitized = first[0]
    assert "alice@example.test" not in sanitized
    assert "phishing@pot" not in sanitized
    assert "202-555-0184" not in sanitized
    assert "XAS66762UK674" not in sanitized
    assert "secret-value" not in sanitized
    assert "private" not in sanitized and "#track" not in sanitized
    assert "<EMAIL_ADDRESS>" in sanitized and "<PHONE_NUMBER>" in sanitized
    assert "<PERSON_NAME>" in sanitized and "<ACCOUNT_ID>" in sanitized
    assert "<URL_DOMAIN>" in sanitized


def test_derived_record_removes_attachment_filename_and_raw_header_values():
    parsed = _parsed(
        plain_body="Email alice@example.test and open https://example.test/x?token=secret",
        authentication_headers={"authentication-results": ["mx.example; spf=pass"]},
        attachments=[{"filename": "alice-secret-invoice.pdf", "content_type": "application/pdf", "bytes": 1234, "sha256": "abc"}],
    )
    record, audit = build_derived_record(parsed, _metadata(), _evidence())
    rendered = json.dumps(record)
    assert "alice-secret-invoice.pdf" not in rendered
    assert "alice@example.test" not in rendered
    assert "token=secret" not in rendered
    assert record["attachment_tokens"] == ["<ATTACHMENT_PDF>"]
    assert audit["attachment_filenames_removed"] == 1


def test_privacy_sanitized_record_is_eligible_with_two_signals():
    record, _ = build_derived_record(_parsed(), _metadata(), _evidence())
    eligible, blockers = weak_label_eligibility(record, _metadata(), _triage())
    assert eligible is True and blockers == []
    assert record["label"] == "phishing"
    assert record["label_quality"] == "weak_source_provenance"
    assert record["review_status"] == "not_manually_reviewed"
    assert record["source_weight"] == .35
    assert record["brand_group"].startswith("brand-unknown-")


def test_irreducible_privacy_blocks_eligibility():
    metadata = _metadata(privacy_unresolved=True)
    record, _ = build_derived_record(_parsed(), metadata, _evidence())
    eligible, blockers = weak_label_eligibility(record, metadata, _triage())
    assert record["privacy_status"] == "privacy_blocked_irreducible"
    assert eligible is False and "privacy_not_sanitized" in blockers


def test_two_independent_signal_requirement():
    record, _ = build_derived_record(_parsed(), _metadata(), _evidence())
    eligible, blockers = weak_label_eligibility(
        record, _metadata(), _triage(independent_evidence_groups=["credential_access_request"]),
    )
    assert eligible is False and "insufficient_independent_evidence" in blockers


def test_attachment_only_and_medium_confidence_are_excluded():
    record, _ = build_derived_record(_parsed(), _metadata(), _evidence())
    eligible, blockers = weak_label_eligibility(
        record, _metadata(), _triage(
            provisional_outcome="medium_confidence_review_required",
            supporting_evidence_categories=["attachment_only"],
        ),
    )
    assert eligible is False
    assert {"attachment_only", "medium_or_non_high_triage"} <= set(blockers)


def test_campaign_and_template_caps():
    rows = [_sample(f"s{i}", "same-campaign", f"t{i}") for i in range(5)]
    selected, excluded = sample_campaign_balanced(rows, existing_phishing_train_rows=100)
    assert len(selected) == 3 and excluded["campaign_cap"] == 2
    rows = [_sample(f"x{i}", f"c{i}", "same-template") for i in range(5)]
    selected, excluded = sample_campaign_balanced(rows, existing_phishing_train_rows=100)
    assert len(selected) == 2 and excluded["template_cap"] == 3


def test_brand_share_cap_and_unknown_brands_are_not_collapsed():
    rows = [_sample(f"b{i}", f"c{i}", f"t{i}", "brand-known") for i in range(5)]
    rows += [_sample(f"u{i}", f"uc{i}", f"ut{i}", "brand-unknown") for i in range(5)]
    selected, excluded = sample_campaign_balanced(rows, existing_phishing_train_rows=100)
    assert sum(row["brand_group"] == "brand-known" for row in selected) <= 2
    assert sum(row["brand_group"] == "brand-unknown" for row in selected) == 5
    assert excluded["brand_share_cap"] >= 3


def test_sampling_is_deterministic_and_weight_policy_is_point_35():
    rows = [_sample(f"s{i}", f"c{i}", f"t{i}") for i in range(8)]
    first = sample_campaign_balanced(rows, existing_phishing_train_rows=100)[0]
    second = sample_campaign_balanced(reversed(rows), existing_phishing_train_rows=100)[0]
    assert [row["sample_id"] for row in first] == [row["sample_id"] for row in second]
    assert WeakSamplingPolicy().weak_sample_weight == .35


def test_schema_defaults_weak_weight_and_preserves_gold_full_weight(tmp_path):
    path = tmp_path / "weighted.csv"
    pd.DataFrame([
        {"text": "Routine project status update", "label": 0, "language": "en", "label_quality": "gold_manual", "split_role": "development_pool", "review_status": "manually_reviewed", "privacy_status": "privacy_sanitized", "template_group": "gold"},
        {"text": "Verify credentials at the portal", "label": 1, "language": "en", "label_quality": "weak_source_provenance", "split_role": "train_only", "review_status": "not_manually_reviewed", "privacy_status": "privacy_sanitized", "template_group": "weak"},
    ]).to_csv(path, index=False)
    frame = load_and_validate_dataset(path)
    weights = dict(zip(frame["label_quality"], frame["source_weight"], strict=True))
    assert weights == {"gold_manual": 1.0, "weak_source_provenance": .35}


def test_training_routes_source_weights_to_classifier():
    class CapturePipeline:
        def fit(self, texts, labels, **kwargs):
            self.kwargs = kwargs
            return self
    pipeline = CapturePipeline()
    fit_with_source_weights(pipeline, ["gold", "weak"], [0, 1], [1.0, .35])
    assert pipeline.kwargs["clf__sample_weight"] == [1.0, .35]


def test_source_policy_is_not_approval_and_needs_no_fabricated_reviewer():
    registry_path = Path(__file__).parents[1] / "config" / "dataset_source_registry.json"
    source = next(row for row in json.loads(registry_path.read_text(encoding="utf-8"))["sources"] if row["source_id"] == "github_rf_peixoto_phishing_pot")
    assert source["approval_status"] == "pending"
    assert source["development_allowed"] is False
    assert "development_mode" not in source
    record, _ = build_derived_record(_parsed(), _metadata(), _evidence())
    assert record["review_status"] == "not_manually_reviewed"
    assert "reviewer" not in record


def test_derived_output_has_no_raw_content_fields():
    record, _ = build_derived_record(_parsed(), _metadata(), _evidence())
    forbidden = {"raw", "raw_body", "message_id", "received", "attachment_filename", "attachment_bytes"}
    assert forbidden.isdisjoint(record)
