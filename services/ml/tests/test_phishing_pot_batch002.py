from __future__ import annotations

import json
from pathlib import Path

from phishshield_ml.dataset import validate_dataset_boundaries
from phishshield_ml.phishing_pot_batch002 import (
    Batch002Policy, batch002_exclusion_reasons, derive_and_assess,
    detect_source_artifacts, leakage_scan_record, sample_batch002,
    select_assessed_candidates, select_batch002_metadata,
)


def _metadata(index: int, **overrides) -> dict:
    row = {
        "candidate_id": f"candidate-{index:06d}", "parse_safe": True, "malformed": False,
        "language": "en", "language_confidence": .99,
        "internal_duplicate_status": "clear", "boundary_overlap": False,
        "boundary_overlap_status": "compared_clear", "phishing_intent": True,
        "provisional_intent_basis": ["url_present", "theme:credential"],
        "campaign_group": f"campaign-{index:06d}", "template_group": f"template-{index:06d}",
        "sender_infrastructure_group": f"infra-{index:06d}", "brand_group": "brand-unknown",
        "theme_group": "credential", "period_bucket": "unknown", "mime_types": ["text/plain"],
        "attachment_count": 0, "privacy_flags": [], "privacy_unresolved": False,
    }
    row.update(overrides)
    return row


def _parsed(body: str = "Verify your password at https://bad.example/login") -> dict:
    return {
        "subject": "Account verification", "plain_body": body, "sanitized_html_text": "",
        "text": f"Subject: Account verification\n\n{body}",
        "sender_domain": "sender.example", "reply_to_domain": "other.example",
        "urls": ["https://bad.example/login"], "authentication_headers": {},
        "mime_types": ["text/plain"], "attachments": [], "privacy": {"flags": []},
    }


def _sample(index: int, **overrides) -> dict:
    row = {
        "sample_id": f"candidate-{index:06d}", "campaign_group": f"campaign-{index}",
        "template_group": f"template-{index}", "brand_group": f"brand-unknown-{index}",
        "sender_infrastructure_group": f"infra-{index}", "source_weight": .35,
        "label_quality": "weak_source_provenance", "split_role": "train_only",
    }
    row.update(overrides)
    return row


def test_batch001_and_endpoint_unavailable_rows_are_excluded():
    row = _metadata(1)
    assert "batch_001_boundary" in batch002_exclusion_reasons(row, batch001_ids={row["candidate_id"]})
    assert "endpoint_security_unavailable" in batch002_exclusion_reasons(
        row, batch001_ids=set(), unavailable_ids={row["candidate_id"]},
    )


def test_deterministic_selection_is_capped_at_500():
    rows = [_metadata(index) for index in range(600)]
    first, _ = select_batch002_metadata(rows, batch001_ids=set())
    second, _ = select_batch002_metadata(reversed(rows), batch001_ids=set())
    assert len(first) == 500
    assert [row["candidate_id"] for row in first] == [row["candidate_id"] for row in second]


def test_campaign_and_template_diversity_caps():
    rows = [_metadata(index, campaign_group="campaign-shared") for index in range(10)]
    selected, excluded = select_batch002_metadata(rows, batch001_ids=set(), policy=Batch002Policy(maximum_selected=10))
    assert len(selected) == 3 and excluded["campaign_selection_cap"] == 7
    rows = [_metadata(index, template_group="template-shared") for index in range(10)]
    selected, excluded = select_batch002_metadata(rows, batch001_ids=set(), policy=Batch002Policy(maximum_selected=10))
    assert len(selected) == 2 and excluded["template_selection_cap"] == 8


def test_sender_infrastructure_and_brand_selection_caps():
    rows = [_metadata(index, sender_infrastructure_group="infra-shared") for index in range(20)]
    selected, _ = select_batch002_metadata(rows, batch001_ids=set(), policy=Batch002Policy(maximum_selected=20))
    assert len(selected) == 1
    rows = [_metadata(index, brand_group="brand-recognized") for index in range(20)]
    selected, _ = select_batch002_metadata(rows, batch001_ids=set(), policy=Batch002Policy(maximum_selected=20))
    assert len(selected) == 3


def test_duplicate_and_boundary_overlap_are_excluded():
    duplicate = _metadata(1, internal_duplicate_status="duplicate")
    overlap = _metadata(2, boundary_overlap=True, boundary_overlap_status="overlap_detected")
    assert "exact_normalized_or_semantic_duplicate" in batch002_exclusion_reasons(duplicate, batch001_ids=set())
    assert "protected_boundary_overlap" in batch002_exclusion_reasons(overlap, batch001_ids=set())


def test_metadata_requires_two_independent_evidence_groups():
    row = _metadata(1, provisional_intent_basis=["theme:credential"])
    assert "insufficient_phishing_evidence" in batch002_exclusion_reasons(row, batch001_ids=set())


def test_final_selection_excludes_medium_and_collection_artifacts():
    good_record = _sample(1)
    rows = [
        (_metadata(1), good_record, {"provisional_outcome": "high_confidence_phishing", "source_artifact_categories": [], "weak_label_eligible": True}),
        (_metadata(2), _sample(2), {"provisional_outcome": "medium_confidence_review_required", "source_artifact_categories": [], "weak_label_eligible": False}),
        (_metadata(3), _sample(3), {"provisional_outcome": "high_confidence_phishing", "source_artifact_categories": ["honeypot_recipient_marker"], "weak_label_eligible": False}),
    ]
    selected, excluded = select_assessed_candidates(rows)
    assert [item[0]["candidate_id"] for item in selected] == ["candidate-000001"]
    assert excluded == {"medium_or_insufficient_static_evidence": 1, "source_collection_artifact": 1}


def test_attachment_only_without_social_engineering_is_excluded():
    row = _metadata(1, attachment_count=1, provisional_intent_basis=["url_present", "urgency_language"])
    assert "attachment_only_without_social_engineering" in batch002_exclusion_reasons(row, batch001_ids=set())


def test_privacy_sanitization_and_leakage_scan():
    raw = b"From: sender@example.test\nTo: phishing@pot\nSubject: Verify\nContent-Type: text/plain\n\nEmail phishing@pot token=secret-value https://bad.example/a?q=private#fragment and verify password."
    record, audit = derive_and_assess(raw, _metadata(1), artifact_exclusion_enabled=False)
    assert record["privacy_status"] == "privacy_sanitized"
    assert leakage_scan_record(record) == []
    rendered = json.dumps(record)
    assert "phishing@pot" not in rendered and "secret-value" not in rendered and "private" not in rendered
    assert audit["leakage_findings"] == []


def test_leakage_scan_rejects_raw_fields_and_addresses():
    findings = leakage_scan_record({"text": "alice@example.test", "attachment_filename": "secret.pdf"})
    assert {"complete_email_address", "forbidden_raw_field"} <= set(findings)


def test_source_and_honeypot_artifacts_are_detected_and_excluded():
    parsed = _parsed("Send to phishing@pot for this phishing_pot honeypot collection")
    categories = detect_source_artifacts(parsed, b"X-Honeypot-ID: synthetic\n")
    assert {"honeypot_recipient_marker", "collection_name_marker", "explicit_honeypot_term", "collection_specific_header"} <= set(categories)
    raw = b"From: sender@example.test\nSubject: Verify\n\nSend credentials to phishing@pot and verify password at https://bad.example/login"
    _, audit = derive_and_assess(raw, _metadata(1), artifact_exclusion_enabled=True)
    assert audit["weak_label_eligible"] is False
    assert "source_collection_artifact" in audit["eligibility_blockers"]


def test_final_sampling_is_deterministic_and_enforces_20_percent_source_share():
    rows = [_sample(index) for index in range(100)]
    first, _ = sample_batch002(rows, existing_phishing_train_rows=100)
    second, _ = sample_batch002(reversed(rows), existing_phishing_train_rows=100)
    assert [row["sample_id"] for row in first] == [row["sample_id"] for row in second]
    assert len(first) == 25
    assert len(first) / (100 + len(first)) <= .20


def test_final_sampling_enforces_sender_and_brand_caps():
    rows = [_sample(index, sender_infrastructure_group="infra-shared") for index in range(100)]
    selected, _ = sample_batch002(rows, existing_phishing_train_rows=400)
    assert len(selected) <= 5
    rows = [_sample(index, brand_group="brand-recognized") for index in range(100)]
    selected, _ = sample_batch002(rows, existing_phishing_train_rows=400)
    assert len(selected) <= 15


def test_batch_rows_keep_weight_and_train_only_boundary():
    row = _sample(1)
    assert row["source_weight"] == .35 and row["split_role"] == "train_only"
    import pandas as pd
    frame = pd.DataFrame([{
        "label": 1, "label_quality": "weak_source_provenance", "split_role": "train_only",
        "review_status": "not_manually_reviewed", "privacy_status": "privacy_sanitized",
    }])
    validate_dataset_boundaries(frame, partition="train")


def test_configuration_does_not_approve_promote_or_train():
    root = Path(__file__).parents[1]
    config = json.loads((root / "config/acquisition_batches/phishing_pot_batch_002.json").read_text(encoding="utf-8"))
    registry = json.loads((root / "config/dataset_source_registry.json").read_text(encoding="utf-8"))
    source = next(item for item in registry["sources"] if item["source_id"] == "github_rf_peixoto_phishing_pot")
    assert config["training_enabled"] is False and config["promotion_eligible"] is False
    assert config["source_approved"] is False
    assert source["approval_status"] == "pending" and source["development_allowed"] is False
