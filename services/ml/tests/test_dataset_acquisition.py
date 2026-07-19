from __future__ import annotations

import io
import base64
import hashlib
import json
import sys
import tarfile
from pathlib import Path

import pytest

from phishshield_ml.acquisition import (
    MAX_MIME_DEPTH,
    MAX_MIME_PARTS,
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
    assert record["attachments"][0]["sha256"] == hashlib.sha256(b"not executable by the parser").hexdigest()
    assert record["attachments"][0]["privacy_safe_filename"]["extension"] == ".bin"
    assert "not executable" not in record["text"]


def test_email_parser_never_fetches_html_remote_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("message-derived network access attempted")

    monkeypatch.setattr("urllib.request.urlopen", fail_network)
    raw = b"""MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<img src="https://tracker.example/pixel?id=secret" data-recipient="private.person@example.test"><a href="https://login.example/path?token=private">Review</a>
"""
    record = parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:remote")
    assert record["remote_resources_blocked"] == 1
    assert record["sanitized_html_text"] == "Review"
    assert "sensitive_url_parameters_require_review" in record["privacy"]["flags"]
    privacy_json = json.dumps(record["privacy"])
    assert "secret" not in privacy_json
    assert "private" not in privacy_json
    assert record["privacy"]["sensitive_html_attribute_count"] >= 1
    assert "sensitive_html_attribute_requires_review" in record["privacy"]["flags"]
    assert {item["host"] for item in record["privacy"]["url_evidence"]} == {
        "login.example", "tracker.example",
    }
    assert {name for item in record["privacy"]["url_evidence"] for name in item["query_parameter_names"]} == {
        "id", "token",
    }


def test_encoded_addresses_are_detected_and_masked_without_exposure() -> None:
    encoded_body = base64.b64encode(b"Contact named.person@example.com for access").decode("ascii")
    raw = f"""From: =?utf-8?q?Named_Person?= <named.person@example.com>
To: honeypot@example.net
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

{encoded_body}
""".encode("ascii")
    record = parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:privacy")
    privacy = record["privacy"]
    assert privacy["decoded_content_address_count"] == 1
    assert privacy["masked_header_addresses"]["from"] == ["n***@example.com"]
    assert privacy["masked_header_addresses"]["to"] == ["h***@example.net"]
    assert "named.person@" not in json.dumps(privacy)
    assert "honeypot@" not in json.dumps(privacy)


def test_sensitive_attachment_name_is_flagged_without_copying_attachment_content() -> None:
    raw = b"""MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: text/plain

Review message
--x
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="account-token-123.exe"

inert bytes only
--x--
"""
    record = parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:attachment")
    assert record["privacy"]["sensitive_attachment_name_count"] == 1
    assert "sensitive_attachment_name_requires_review" in record["privacy"]["flags"]
    assert "inert bytes only" not in record["text"]


def test_malformed_mime_is_flagged_without_exposing_content() -> None:
    raw = b"""MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=unfinished

--unfinished
Content-Type: text/plain

safe visible text
"""
    record = parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:malformed")
    assert record["malformed"] is True
    assert record["parse_warnings"]
    assert "safe visible text" in record["text"]


def test_malformed_url_evidence_is_inert_and_does_not_break_parsing() -> None:
    record = parse_email_bytes(
        b"Content-Type: text/plain\n\nReview http://[invalid-host/path",
        source_id="fixture",
        campaign_id="fixture:bad-url",
    )
    assert record["privacy"]["url_evidence"][0]["malformed"] is True


def test_mime_part_limit_rejects_part_bombs() -> None:
    parts = [
        b"--many\nContent-Type: text/plain\n\nx\n" for _ in range(MAX_MIME_PARTS + 1)
    ]
    raw = b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=many\n\n" + b"".join(parts) + b"--many--\n"
    with pytest.raises(ValueError, match="MIME parts"):
        parse_email_bytes(raw, source_id="fixture", campaign_id="fixture:parts")


def test_mime_depth_limit_rejects_deep_nesting() -> None:
    headers = b"MIME-Version: 1.0\n"
    body = b""
    for depth in range(MAX_MIME_DEPTH + 2):
        boundary = f"depth-{depth}".encode("ascii")
        body += b"Content-Type: multipart/mixed; boundary=" + boundary + b"\n\n--" + boundary + b"\n"
    body += b"Content-Type: text/plain\n\nx\n"
    for depth in reversed(range(MAX_MIME_DEPTH + 2)):
        body += b"--depth-" + str(depth).encode("ascii") + b"--\n"
    with pytest.raises(ValueError, match="MIME depth"):
        parse_email_bytes(headers + body, source_id="fixture", campaign_id="fixture:depth")


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
