from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishshield_ml.source_artifact_normalization import (  # noqa: E402
    normalize_for_source_probe,
    normalize_records,
)


def test_normalizes_transport_and_collection_artifacts() -> None:
    raw = (
        "Message-ID: <unique-123@example.invalid>\n"
        "Received: from honeypot-7 by mx.example\n"
        "X-Honeypot-ID: mailbox-77\n"
        "To: honeytrap@example.invalid\n"
        "Content-Type: multipart/alternative; boundary=abc987\n"
        "X-MimeOLE: Produced By Microsoft\n"
        "https://example.invalid/login?utm_campaign=secret&x=1 <!-- generator id -->"
    )
    result = normalize_for_source_probe(raw)
    assert "unique-123" not in result.text
    assert "honeypot-7" not in result.text
    assert "mailbox-77" not in result.text
    assert "boundary=abc987" not in result.text
    assert "<message-id>" in result.text
    assert "<received>" in result.text
    assert "<collection-recipient>" in result.text
    assert "utm_campaign=<tracking>" in result.text
    assert "<!--" not in result.text
    assert "normalize_message_id" in result.actions


def test_preserves_phishing_semantics_and_non_collection_addresses() -> None:
    raw = (
        "From: security@example.com\n"
        "To: analyst@example.com\n"
        "Subject: Urgent account password verification\n"
        "Please login and enter your password at https://example.com/login"
    )
    result = normalize_for_source_probe(raw)
    assert "Urgent account password verification" in result.text
    assert "Please login and enter your password" in result.text
    assert "https://example.com/login" in result.text
    assert "analyst@example.com" in result.text
    assert not result.actions


def test_batch_api_returns_privacy_safe_transform_log() -> None:
    values, log = normalize_records(["X-Source-ID: abc\nbody", "plain text"])
    assert values[0] == "body"
    assert values[1] == "plain text"
    assert log[0]["changed"] is True
    assert log[0]["transforms"] == ["remove_collection_headers"]
    assert log[1]["changed"] is False

