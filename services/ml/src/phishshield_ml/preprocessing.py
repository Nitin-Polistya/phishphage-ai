"""Conservative preprocessing helpers for phishing text classification."""

from __future__ import annotations

import re
import unicodedata


WHITESPACE_RE = re.compile(r"\s+")


def normalize_email_text(text: object) -> str:
    if text is None:
        return ""
    value = str(text)
    value = unicodedata.normalize("NFKC", value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = WHITESPACE_RE.sub(" ", value).strip()
    return value


def combine_email_fields(subject: object | None, body: object | None) -> str:
    subject_text = normalize_email_text(subject)
    body_text = normalize_email_text(body)
    if subject_text and body_text:
        return f"{subject_text} {body_text}"
    return subject_text or body_text


def validate_training_text(text: object) -> str:
    normalized = normalize_email_text(text)
    if not normalized:
        raise ValueError("Training text cannot be empty")
    return normalized
