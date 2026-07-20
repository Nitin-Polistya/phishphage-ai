"""Privacy-safe, source-probe-only normalization for collection artifacts.

This module deliberately operates on probe text, never on the classifier's
training corpus.  Transforms are limited to transport/collection metadata and
tracking identifiers; phishing semantics (requests, brands, URLs and security
signals) are preserved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizationResult:
    text: str
    actions: tuple[str, ...]


# Audit metadata consumed by the B.3E report generator.  Only entries marked
# SAFE_TO_REMOVE or SAFE_TO_NORMALIZE are implemented below; phishing-relevant
# fields (authentication, credentials, URLs, urgency, brands) are intentionally
# absent and therefore remain KEEP in the inventory.
ARTIFACT_CLASSIFICATION: dict[str, dict[str, str]] = {
    "collection_headers": {"category": "SAFE_TO_REMOVE", "justification": "Explicit X-* collection markers identify the honeypot, not the message threat."},
    "message_id": {"category": "SAFE_TO_NORMALIZE", "justification": "Transport identifier is unique per message and has no phishing semantics."},
    "received_chain": {"category": "SAFE_TO_NORMALIZE", "justification": "Collection route/timestamps create source fingerprints; preserve only a placeholder."},
    "mime_boundary": {"category": "SAFE_TO_NORMALIZE", "justification": "Generated boundary strings are transport boilerplate."},
    "mime_generator_headers": {"category": "SAFE_TO_REMOVE", "justification": "Known generator headers are client/collector fingerprints."},
    "honeypot_recipient": {"category": "SAFE_TO_NORMALIZE", "justification": "Recipient marker is collection metadata; ordinary recipients are retained."},
    "tracking_query_values": {"category": "SAFE_TO_NORMALIZE", "justification": "Tracking values identify campaigns/collection, while URL host/path remain intact."},
    "html_comments": {"category": "SAFE_TO_REMOVE", "justification": "Comments are non-visible generator or campaign metadata."},
}


_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Explicit collection headers are not email semantics.
    ("remove_collection_headers", re.compile(r"(?im)^(?:x-(?:honeypot|phishing[-_ ]?pot|collection|source)[^:]*):[^\r\n]*(?:\r?\n|$)"), ""),
    # Normalize, rather than delete, standard transport identifiers.
    ("normalize_message_id", re.compile(r"(?im)^(message-id):[^\r\n]*(?:\r?\n|$)"), r"\1: <message-id>\n"),
    ("normalize_received", re.compile(r"(?im)^(received):[^\r\n]*(?:\r?\n|$)"), r"\1: <received>\n"),
    ("normalize_mime_boundary", re.compile(r"(?i)(boundary\s*=\s*[\"']?)([^\"';\s]+)"), r"\1<boundary>"),
    ("remove_generator_headers", re.compile(r"(?im)^(?:x-mimeole|x-mime-autoconverted):[^\r\n]*(?:\r?\n|$)"), ""),
    # Honeypot recipient markers are collection metadata; preserve other
    # recipient addresses and all sender/security fields.
    ("normalize_collection_recipient", re.compile(r"(?i)(<(?:to|cc|bcc|delivered-to)>|(?:to|cc|bcc|delivered-to):)\s*[^\r\n]*(?:honeypot|honeytrap|spamtrap|sinkhole|phishing[-_ ]?pot)[^\r\n]*(?:\r?\n|$)"), r"\1 <collection-recipient>\n"),
    # Tracking query values are collection identifiers, not phishing
    # concepts.  Keep parameter names and URL hosts/paths intact.
    ("normalize_tracking_parameters", re.compile(r"(?i)([?&](?:utm_[a-z0-9_]+|(?:trk|tracking|trackid|cid|campaign_id))=)[^&#\s>]+"), r"\1<tracking>"),
    # HTML comments commonly contain generator/campaign IDs.  Visible text,
    # hrefs and credential language are intentionally retained.
    ("remove_html_comments", re.compile(r"(?is)<!--.*?-->"), ""),
)


def normalize_for_source_probe(text: str) -> NormalizationResult:
    """Apply only approved collection-artifact transforms to *text*.

    The returned action names are deterministic and suitable for an audit log.
    No network access, HTML rendering, URL fetching, or classifier mutation is
    performed.
    """

    value = str(text or "")
    actions: list[str] = []
    for name, pattern, replacement in _RULES:
        value, count = pattern.subn(replacement, value)
        if count:
            actions.extend([name] * count)
    # Collapse transport whitespace only after metadata removal.  Do not
    # lowercase or otherwise alter lexical phishing indicators.
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value).strip()
    return NormalizationResult(value, tuple(actions))


def normalize_records(texts: list[str] | tuple[str, ...]) -> tuple[list[str], list[dict[str, object]]]:
    """Normalize a sequence and return text plus privacy-safe transform log."""

    normalized: list[str] = []
    log: list[dict[str, object]] = []
    for index, text in enumerate(texts):
        result = normalize_for_source_probe(text)
        normalized.append(result.text)
        log.append({"row": index, "transforms": list(result.actions), "changed": result.text != str(text or "")})
    return normalized, log
