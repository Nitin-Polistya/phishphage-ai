from __future__ import annotations

import json
from pathlib import Path

from phishshield_ml.artifact_reduction import ARTIFACT_DEFINITIONS, normalize_text
from phishshield_ml.source_artifact_normalization import normalize_for_source_probe, normalize_records


def test_probe_normalization_removes_collection_transport_artifacts_only() -> None:
    raw = (
        "X-Honeypot-Id: mailbox-123\n"
        "Message-ID: <unique-123@example.invalid>\n"
        "Received: from collector.example\n"
        "To: <honeytrap@example.invalid>\n"
        "Subject: Urgent password reset\n"
        "<!-- generator campaign-987 -->\n"
        "Please login at https://example.com/reset?tracking=secret and confirm your password."
    )
    result = normalize_for_source_probe(raw)
    assert "mailbox-123" not in result.text
    assert "unique-123@example.invalid" not in result.text
    assert "campaign-987" not in result.text
    # Security semantics and URL host/path remain available to the probe.
    assert "password" in result.text.lower()
    assert "https://example.com/reset" in result.text
    assert "remove_collection_headers" in result.actions
    assert "normalize_message_id" in result.actions


def test_legacy_normalize_text_preserves_phishing_indicators() -> None:
    text = "Subject: Urgent invoice\nConfirm your password at https://evil.test/login?utm_campaign=abc"
    normalized, actions = normalize_text(text)
    assert "password" in normalized
    assert "evil.test/login" in normalized
    assert "utm_campaign=<TRACKING_ID>" in normalized
    assert "tracking_ids" in actions


def test_batch_transform_log_is_privacy_safe() -> None:
    values, log = normalize_records(["X-Collection: private-mailbox\nMessage-ID: <secret>"])
    assert len(values) == len(log) == 1
    encoded = json.dumps(log)
    assert "private-mailbox" not in encoded
    assert "secret" not in encoded
    assert log[0]["changed"] is True


def test_artifact_inventory_classifies_all_requested_families() -> None:
    names = {name for name, _classification, _pattern in ARTIFACT_DEFINITIONS}
    required = {
        "headers", "sender_domains", "recipient_patterns", "subject_prefixes",
        "message_ids", "reply_to", "authentication", "url_domains", "url_paths",
        "html_comments", "css", "hidden_text", "footer_text", "lexical_tokens",
        "whitespace_patterns", "character_encoding", "mime_structure",
        "attachment_metadata", "collection_metadata",
    }
    assert required <= names


def test_only_safe_classes_are_eligible_for_automatic_transforms() -> None:
    classes = {name: classification for name, classification, _pattern in ARTIFACT_DEFINITIONS}
    safe = {name for name, classification in classes.items() if classification.startswith("SAFE_")}
    # Keep/experimental signals must remain review-only, even if a probe ranks
    # them highly; this prevents accidental semantic feature removal.
    assert "authentication" not in safe
    assert "lexical_tokens" not in safe
    assert "url_domains" not in safe
    assert {"message_ids", "html_comments", "collection_metadata"} <= safe


def test_artifact_reports_are_ignored_and_not_checked_in() -> None:
    root = Path(__file__).resolve().parents[1]
    ignore = root.parents[1].joinpath(".gitignore").read_text(encoding="utf-8")
    assert "services/ml/reports/*" in ignore
    assert "!services/ml/reports/.gitkeep" in ignore
    assert "services/ml/data/raw/*" in ignore
    assert "services/ml/data/interim/*" in ignore
    assert "services/ml/data/processed/*" in ignore
    assert "services/ml/data/external/*" in ignore
