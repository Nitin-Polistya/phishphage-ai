from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from phishshield_ml.acquisition import (
    assert_not_external_path,
    load_source_registry,
    parse_email_bytes,
    safe_archive_members,
    validate_download_source,
    verify_expected_checksum,
)
from phishshield_ml.training import train_model


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from deduplicate_and_group import deduplicate


def test_registry_blocks_sources_without_clear_reuse_license() -> None:
    _, sources = load_source_registry(ROOT / "dataset_sources.json")
    assert sources["cmu_enron_20150507"].status == "blocked"
    assert sources["apache_spamassassin_easy_ham"].status == "blocked"
    assert sources["apache_spamassassin_spam"].assigned_project_label is None
    with pytest.raises(PermissionError):
        validate_download_source(sources["cmu_enron_20150507"])


def test_only_explicitly_licensed_zenodo_sources_are_downloadable() -> None:
    _, sources = load_source_registry(ROOT / "dataset_sources.json")
    approved = {source.id for source in sources.values() if source.status == "approved"}
    assert approved == {
        "zenodo_phishing_nlp_15235123",
        "zenodo_phishing_validation_13474746",
    }
    for source_id in approved:
        validate_download_source(sources[source_id])


def test_email_parser_extracts_safe_text_headers_urls_and_attachment_metadata() -> None:
    raw = b"""From: Alerts <notice@example.test>
Reply-To: agent@reply.example
Subject: Account security reminder
Authentication-Results: mx.example; spf=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/html; charset=utf-8

<html><script>fetch('https://must-not-appear.test')</script><body>
Review <a href="https://example.test/review">your account</a> safely.
</body></html>
--x
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="sample.bin"

not executable by the parser
--x--
"""
    record = parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:one")
    assert "Account security reminder" in record["text"]
    assert "your account" in record["sanitized_html_text"]
    assert "must-not-appear" not in record["sanitized_html_text"]
    assert record["sender_domain"] == "example.test"
    assert record["reply_to_domain"] == "reply.example"
    assert record["urls"] == ["https://example.test/review"]
    assert record["authentication_headers"]["authentication-results"] == ["mx.example; spf=pass"]
    assert record["attachments"][0]["filename"] == "sample.bin"
    assert "not executable" not in record["text"]


def test_archive_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        payload = b"message"
        member = tarfile.TarInfo("../outside")
        member.size = len(payload)
        handle.addfile(member, io.BytesIO(payload))
    with pytest.raises(ValueError, match="Unsafe archive member"):
        safe_archive_members(archive)


def test_expected_checksum_is_enforced(tmp_path: Path) -> None:
    sample = tmp_path / "sample.dat"
    sample.write_bytes(b"known")
    checksums = verify_expected_checksum(sample, "md5:c90ae688b2a3b1fd0751fd743eb385cd")
    assert checksums["sha256"]
    with pytest.raises(ValueError, match="Checksum mismatch"):
        verify_expected_checksum(sample, "md5:00000000000000000000000000000000")


def test_external_paths_cannot_be_used_as_core_input(tmp_path: Path) -> None:
    external = tmp_path / "external" / "validation.jsonl"
    with pytest.raises(ValueError, match="physically isolated"):
        assert_not_external_path(external)


def test_training_rejects_external_validation_inputs(tmp_path: Path) -> None:
    external = tmp_path / "external" / "validation.csv"
    with pytest.raises(ValueError, match="physically isolated"):
        train_model(external, tmp_path / "model.joblib", tmp_path / "metrics.json")
    with pytest.raises(ValueError, match="Training cannot read external-validation data"):
        train_model(tmp_path / "core.csv", tmp_path / "model.joblib", tmp_path / "metrics.json", external_dataset_path=external)


def test_exact_and_near_template_duplicates_are_removed() -> None:
    rows = [
        {"text": "Reset account at https://one.example/login code 12345", "label": 1, "source": "a", "campaign_id": "a:one"},
        {"text": "Reset account at https://one.example/login code 12345", "label": 1, "source": "a", "campaign_id": "a:one"},
        {"text": "Reset account at https://two.example/login code 98765", "label": 1, "source": "a", "campaign_id": "a:two"},
        {"text": "Project meeting is Tuesday in the established workspace", "label": 0, "source": "b", "campaign_id": "b:one"},
    ]
    clean, removed = deduplicate(rows)
    assert len(clean) == 2
    assert removed == {"exact_duplicate": 1, "canonical_template_duplicate": 1}
    assert all(row["template_group"] for row in clean)


def test_registry_is_json_and_records_required_provenance_fields() -> None:
    payload = json.loads((ROOT / "dataset_sources.json").read_text(encoding="utf-8"))
    required = {
        "official_page", "license", "expected_checksum", "archive_filename",
        "original_label_meaning", "assigned_project_label", "language_scope",
    }
    assert payload["audited_on"]
    assert all(required <= set(source) for source in payload["sources"])
