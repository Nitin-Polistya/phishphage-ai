from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishshield_ml.gold_dataset_evaluation import (
    ApprovedContentRecord,
    DuplicateGoldHashError,
    GoldApprovalError,
    GoldEvaluationInput,
    GoldExportRecord,
    GoldPrivacyError,
    GoldSchemaError,
    adapt_approved_records,
    build_evaluation_report,
    load_export_records,
    privacy_safe_artifact_text,
)


def _digest(value: str) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _values(
    review_id: str,
    label: str = "safe",
    *,
    sample_hash: str | None = None,
    source_sample_id: str | None = None,
    source_dataset: str = "trusted-dataset",
    campaign: str | None = None,
) -> dict:
    sample_hash = sample_hash or f"sample-{review_id}"
    source_sample_id = source_sample_id or f"source-{review_id}"
    campaign = campaign or f"campaign-{review_id}"
    return {
        "campaign_identifier": _digest(campaign),
        "export_version": "gold-dataset-v1",
        "human_label_authority": True,
        "label_quality": "high",
        "language": "en",
        "phishing_label": label,
        "review_id": review_id,
        "review_notes": "[redacted for privacy-safe export]",
        "review_version": "review-v1",
        "reviewer_confidence": 0.99,
        "sample_hash": _digest(sample_hash),
        "source_dataset": _digest(source_dataset),
        "source_sample_id_digest": _digest(source_sample_id),
    }


def _content(
    review_id: str,
    label: str = "safe",
    *,
    normalized_hash: str | None = None,
    sample_hash: str | None = None,
    source_sample_id: str | None = None,
    source_dataset: str = "trusted-dataset",
    campaign: str | None = None,
    state: str = "approved",
) -> ApprovedContentRecord:
    sample_hash = sample_hash or f"sample-{review_id}"
    source_sample_id = source_sample_id or f"source-{review_id}"
    campaign = campaign or f"campaign-{review_id}"
    return ApprovedContentRecord(
        review_id=review_id,
        state=state,
        sample_hash=sample_hash,
        normalized_content_hash=normalized_hash or f"normalized-{review_id}",
        source_dataset=source_dataset,
        source_sample_id=source_sample_id,
        campaign_identifier=campaign,
        phishing_label=label,
        subject="Routine account notice",
        body_excerpt="This is a short sanitized message excerpt.",
    )


def test_schema_conversion_maps_labels_and_stable_orders_records() -> None:
    first = GoldExportRecord(2, _values("b", "phishing"))
    second = GoldExportRecord(1, _values("a", "safe"))

    adapted = adapt_approved_records(
        [first, second],
        {"a": _content("a", "safe"), "b": _content("b", "phishing")},
    )

    assert [record.sample_id for record in adapted] == [_digest("source-a"), _digest("source-b")]
    assert [(record.label_name, record.label) for record in adapted] == [("safe", 0), ("phishing", 1)]
    assert all("Routine account notice" in record.text for record in adapted)


def test_load_export_records_rejects_malformed_schema(tmp_path: Path) -> None:
    path = tmp_path / "gold.jsonl"
    values = _values("one")
    del values["sample_hash"]
    path.write_text(json.dumps(values) + "\n", encoding="utf-8")

    with pytest.raises(GoldSchemaError, match="Malformed gold record"):
        load_export_records(path)


def test_load_export_records_rejects_duplicate_hashes(tmp_path: Path) -> None:
    first = _values("one", sample_hash="same-hash")
    second = _values("two", sample_hash="same-hash")
    path = tmp_path / "gold.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in (first, second)) + "\n", encoding="utf-8")

    with pytest.raises(DuplicateGoldHashError, match="Duplicate sample hash"):
        load_export_records(path)


def test_only_approved_records_are_loaded() -> None:
    record = GoldExportRecord(1, _values("one"))

    with pytest.raises(GoldApprovalError, match="approved review"):
        adapt_approved_records([record], {"one": _content("one", state="reviewed")})


def test_label_mismatch_is_rejected() -> None:
    record = GoldExportRecord(1, _values("one", "phishing"))

    with pytest.raises(GoldApprovalError, match="label"):
        adapt_approved_records([record], {"one": _content("one", "safe")})


def test_duplicate_normalized_hash_is_rejected() -> None:
    first = GoldExportRecord(1, _values("one"))
    second = GoldExportRecord(2, _values("two"))

    with pytest.raises(DuplicateGoldHashError, match="normalized-content"):
        adapt_approved_records(
            [first, second],
            {"one": _content("one", normalized_hash="duplicate"), "two": _content("two", normalized_hash="duplicate")},
        )


def test_privacy_unsafe_content_fails_closed() -> None:
    record = GoldExportRecord(1, _values("one"))
    unsafe = _content("one")
    unsafe = unsafe.__class__(**{**unsafe.__dict__, "body_excerpt": "Contact person@example.com at https://example.invalid/x"})

    with pytest.raises(GoldPrivacyError, match="privacy safety"):
        adapt_approved_records([record], {"one": unsafe})


def test_metric_correctness_and_privacy_safe_misclassification_rows() -> None:
    records = [
        GoldEvaluationInput("sample-a", "sha256:source-a", "safe", 0, "safe text", "sha256:a", "norm-a"),
        GoldEvaluationInput("sample-b", "sha256:source-b", "safe", 0, "safe text", "sha256:b", "norm-b"),
        GoldEvaluationInput("sample-c", "sha256:source-a", "phishing", 1, "phish text", "sha256:c", "norm-c"),
        GoldEvaluationInput("sample-d", "sha256:source-b", "phishing", 1, "phish text", "sha256:d", "norm-d"),
    ]
    report = build_evaluation_report(records, [0.1, 0.9, 0.2, 0.8], 0.5)

    assert report["sample_count"] == 4
    assert report["class_distribution"] == {"safe": 2, "phishing": 2}
    assert report["confusion_matrix"]["matrix"] == [[1, 1], [1, 1]]
    assert report["accuracy"] == 0.5
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert report["f1"] == 0.5
    assert report["false_positive_count"] == 1
    assert report["false_negative_count"] == 1
    assert len(report["misclassifications"]) == 2
    for row in report["misclassifications"]:
        assert set(row) == {"sample_id", "expected_label", "predicted_label", "phishing_probability", "threshold"}
        assert "text" not in row
        assert "source_dataset" not in row


def test_output_privacy_gate_rejects_sensitive_artifact_text() -> None:
    assert privacy_safe_artifact_text('{"sample_id":"sha256:abc"}')
    assert not privacy_safe_artifact_text("person@example.com")
    assert not privacy_safe_artifact_text("https://example.invalid/path?token=secret")
    assert not privacy_safe_artifact_text("C:\\private\\message.eml")
