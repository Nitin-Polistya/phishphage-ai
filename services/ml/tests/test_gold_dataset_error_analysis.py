from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from phishshield_ml.gold_dataset_error_analysis import (
    AnalysisObservation,
    ErrorAnalysisValidationError,
    calibration_report,
    feature_prevalence_rows,
    group_rows,
    output_file_hashes,
    probability_band_rows,
    privacy_safe_error_artifact_text,
    select_false_negatives,
    threshold_rows,
)


def _observation(
    sample_id: str,
    label: str,
    probability: float,
    *,
    sample_hash: str | None = None,
    campaign: str = "campaign-a",
    features: dict[str, int] | None = None,
    text_length: int = 100,
    token_count: int = 20,
    oov: float = 0.1,
    signals: tuple[str, ...] = (),
) -> AnalysisObservation:
    return AnalysisObservation(
        sample_id=sample_id,
        sample_hash=sample_hash or f"hash-{sample_id}",
        source_dataset="sha256:source",
        campaign_id=f"sha256:{campaign}",
        language="en",
        label=label,
        probability=probability,
        features=features or {},
        text_length=text_length,
        token_count=token_count,
        vocabulary_coverage=1.0 - oov,
        oov_proportion=oov,
        nonzero_features=10,
        nonzero_selected_features=3,
        strong_rule_signal_count=1 if signals else 0,
        rule_signal_count=len(signals),
        rule_signal_codes=signals,
        authentication_bucket="absent_from_retained_metadata",
        url_bucket="no_retained_url_evidence",
        sender_domain_category="absent_from_retained_metadata",
        attachment_category="no_retained_attachment_metadata",
    )


def test_exact_false_negative_selection_and_stable_ordering() -> None:
    observations = [
        _observation("b", "phishing", 0.2),
        _observation("a", "phishing", 0.1),
        _observation("c", "phishing", 0.5),
        _observation("d", "safe", 0.1),
    ]

    selected = select_false_negatives(observations, 0.5)

    assert [item.sample_id for item in selected] == ["a", "b"]


def test_duplicate_hashes_are_rejected() -> None:
    observations = [_observation("a", "phishing", 0.1, sample_hash="same"), _observation("b", "safe", 0.1, sample_hash="same")]

    with pytest.raises(ErrorAnalysisValidationError, match="Duplicate sample hash"):
        select_false_negatives(observations, 0.5)


def test_probability_band_boundaries_are_lower_inclusive_upper_exclusive() -> None:
    probabilities = [0.099, 0.1, 0.199, 0.2, 0.299, 0.3, 0.399, 0.4, 0.499]
    rows = probability_band_rows(
        [_observation(f"s{index}", "phishing", probability) for index, probability in enumerate(probabilities)],
        cohort_name="false_negative",
    )

    assert [row["count"] for row in rows] == [1, 2, 2, 2, 2]
    assert sum(row["count"] for row in rows) == 9


def test_feature_prevalence_compares_fn_tp_and_safe() -> None:
    observations = [
        _observation("fn", "phishing", 0.1, features={"credential_request": 1, "shared": 1}),
        _observation("tp", "phishing", 0.9, features={"shared": 1, "tp_only": 1}),
        _observation("safe", "safe", 0.1, features={"safe_only": 1}),
    ]

    rows = {row["feature"]: row for row in feature_prevalence_rows(observations, 0.5)}

    assert rows["credential_request"]["fn_prevalence"] == 1.0
    assert rows["credential_request"]["tp_prevalence"] == 0.0
    assert rows["tp_only"]["fn_prevalence"] == 0.0
    assert rows["shared"]["fn_minus_tp"] == 0.0


def test_threshold_metrics_are_binary_phishing_aware() -> None:
    observations = [
        _observation("safe-low", "safe", 0.05),
        _observation("safe-high", "safe", 0.2),
        _observation("phish-low", "phishing", 0.15),
        _observation("phish-high", "phishing", 0.8),
    ]

    row = threshold_rows(observations, [0.1])[0]

    assert row["tp"] == 2
    assert row["fp"] == 1
    assert row["tn"] == 1
    assert row["fn"] == 0
    assert row["precision"] == pytest.approx(2 / 3)
    assert row["recall"] == 1.0
    assert row["balanced_accuracy"] == pytest.approx(0.75)
    assert row["hypothetical"] is True


def test_group_assignment_is_explainable_and_overlapping() -> None:
    observations = [
        _observation(
            "fn-a", "phishing", 0.1, campaign="same", features={"credential_request": 1, "financial_claim": 1},
            text_length=20, token_count=4, signals=("content_credential_request",),
        ),
        _observation("fn-b", "phishing", 0.2, campaign="same", text_length=200, token_count=30),
    ]

    rows = {row["group"]: row for row in group_rows(observations, 0.5)}

    assert rows["credential_phishing"]["count"] == 1
    assert rows["financial_payment_claim"]["count"] == 1
    assert rows["short_or_sparse_text"]["count"] == 1
    assert rows["repeated_campaign_family"]["count"] == 2
    assert rows["sanitized_limited_context"]["count"] == 2


def test_calibration_report_does_not_fit_a_calibrator() -> None:
    observations = [
        _observation("safe", "safe", 0.1),
        _observation("phish", "phishing", 0.9),
    ]

    report = calibration_report(observations, 0.5)

    assert report["method"].startswith("fixed reliability bins")
    assert report["expected_calibration_error"] == pytest.approx(0.1)
    assert report["threshold_unchanged"] == 0.5


def test_manifest_hashes_are_deterministic(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text("{\"safe\":true}\n", encoding="utf-8")
    (tmp_path / "b.csv").write_text("count\n1\n", encoding="utf-8")

    first = output_file_hashes(str(tmp_path), ["a.json", "b.csv"])
    second = output_file_hashes(str(tmp_path), ["a.json", "b.csv"])

    assert first == second
    assert all(len(value) == 64 for value in first.values())


def test_privacy_safe_artifact_gate_rejects_private_content() -> None:
    assert privacy_safe_error_artifact_text("feature=credential_request count=2")
    assert not privacy_safe_error_artifact_text("person@example.com")
    assert not privacy_safe_error_artifact_text("https://example.invalid/path?token=secret")
    assert not privacy_safe_error_artifact_text("Received: from private-host")
    assert not privacy_safe_error_artifact_text("<html>private</html>")
    assert not privacy_safe_error_artifact_text("C:\\private\\message.eml")
    assert not privacy_safe_error_artifact_text("admin_token=super-secret")


def test_registered_model_state_is_read_only() -> None:
    root = Path(__file__).resolve().parents[3]
    registry_path = root / "services" / "ml" / "models" / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    record = registry["models"][0]
    artifact = root / "services" / "ml" / "artifacts" / "phase_c_model_development_v1" / "deployment_candidate" / "fitted_pipeline.joblib"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    assert record["activated"] is False
    assert record["sha256"] == digest


def test_generated_error_analysis_artifacts_are_privacy_safe() -> None:
    root = Path(__file__).resolve().parents[3] / "services" / "ml" / "evaluation" / "private" / "gold_dataset_error_analysis"
    if not root.exists():
        pytest.skip("Private analysis artifacts are not present in this checkout.")
    text = "\n".join(path.read_text(encoding="utf-8") for path in root.iterdir() if path.is_file())
    assert privacy_safe_error_artifact_text(text)
    assert not re.search(r"(?i)(?:[A-Za-z]:[\\/]|/Users/|/home/|/tmp/|/var/)", text)
    manifest = json.loads((root / "error_analysis_manifest.json").read_text(encoding="utf-8"))
    for relative_name, expected_hash in manifest["output_file_sha256"].items():
        path = Path(relative_name.replace("/", "\\"))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash
