"""Prepare the Phase IV.B privacy-safe metadata-rich review pilot.

The utility is deterministic and intentionally separate from model inference.
It reads local source/derived records, writes only sanitized CSV/JSON/Markdown
under the ignored evaluation-private directory, and uses a temporary pending
only SQLite store for importer compatibility checks.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import html
import json
import re
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


SCRIPT_VERSION = "rich-metadata-pilot-v1"
TARGET_SAFE = 25
TARGET_PHISHING = 25
OUT_RELATIVE = Path("services/ml/evaluation/private/dataset_review_rich_metadata_pilot")
HEADERS = [
    "source_sample_id",
    "source_dataset",
    "source_claimed_label",
    "campaign_id",
    "language",
    "subject",
    "body_excerpt",
    "sender_domain",
    "reply_to_domain",
    "authentication_summary",
    "url_domains",
    "url_structural_flags",
    "attachment_extension",
    "attachment_mime",
    "normalized_content_hash",
    "sample_hash",
]

EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?|ftp|javascript|data|file|blob|chrome):[^\s<>\"']+")
WWW_RE = re.compile(r"(?i)\bwww\.[^\s<>\"']+")
PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d .()\-]{7,}\d(?!\w)")
PATH_RE = re.compile(r"(?i)(?:[A-Za-z]:\\|\\\\|/Users/|/home/|/tmp/|/var/|file://)[^\s]+")
HEADER_LINE_RE = re.compile(
    r"(?im)^(?:from|to|cc|bcc|subject|received|message-id|authentication-results|return-path|reply-to|date):.*$"
)
HTML_BLOCK_RE = re.compile(r"(?is)<(?:script|style|template|svg|object|embed|iframe|form|noscript|head)[^>]*>.*?</(?:script|style|template|svg|object|embed|iframe|form|noscript|head)>")
HTML_TAG_RE = re.compile(r"(?is)<[^>]{1,500}>")
TOKEN_RE = re.compile(r"(?i)\b(?:token|secret|api[_ -]?key|authorization|bearer|cookie|session)[ :=_-]*[^\s,;]{8,}")
QUERY_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+\?[^\s<>\"']*")
ABSOLUTE_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\|/Users/|/home/|/tmp/|/var/|\\\\)")
FULL_URL_OUTPUT_RE = re.compile(r"(?i)\b(?:https?|ftp)://|\bwww\.")
RAW_HEADER_OUTPUT_RE = re.compile(r"(?im)^(?:from|to|received|message-id|authentication-results|return-path):")

SAFE_CATEGORIES = ("corporate", "personal", "transaction")
PHISH_FAMILIES = ("credential", "account_security", "invoice_payment", "delivery", "qr_or_mfa")


class _VisibleTextParser(HTMLParser):
    """Small local HTML-to-text reducer; never renders or fetches HTML."""

    ignored = {"script", "style", "template", "svg", "object", "embed", "iframe", "form", "noscript", "head"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in self.ignored:
            self.depth += 1
        if self.depth == 0 and tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self.ignored and self.depth:
            self.depth -= 1
        if self.depth == 0 and tag.lower() in {"br", "p", "div", "li", "tr"}:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self.depth == 0:
            self.parts.append(data)


def visible_text(value: str) -> str:
    if "<" not in value or ">" not in value:
        return value
    parser = _VisibleTextParser()
    try:
        parser.feed(value[:100_000])
        parser.close()
    except Exception:
        return ""
    return " ".join(parser.parts)


def sanitize_text(value: object, limit: int) -> str:
    text = html.unescape(str(value or "")).replace("\x00", " ")
    text = visible_text(text)
    text = HTML_BLOCK_RE.sub(" ", text)
    text = HEADER_LINE_RE.sub(" [header removed] ", text)
    text = QUERY_RE.sub(" [URL removed] ", text)
    text = URL_RE.sub(" [URL removed] ", text)
    text = WWW_RE.sub(" [URL removed] ", text)
    text = EMAIL_RE.sub(" [email address removed] ", text)
    text = PHONE_RE.sub(" [phone number removed] ", text)
    text = PATH_RE.sub(" [local path removed] ", text)
    text = TOKEN_RE.sub(" [credential-like value removed] ", text)
    text = HTML_TAG_RE.sub(" ", text)
    text = re.sub(r"(?i)\b(?:dear|hello|hi)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", lambda m: m.group(0).split()[0] + " [name removed]", text)
    text = re.sub(r"[\r\n\t ]+", " ", text).strip()
    return text[:limit].rstrip()


def extract_domains(value: object) -> list[str]:
    text = str(value or "")
    domains: list[str] = []
    for match in [*URL_RE.findall(text), *WWW_RE.findall(text)]:
        raw = match.strip(".,;:)]}>\"'")
        if raw.lower().startswith("www."):
            raw = "http://" + raw
        raw = re.sub(r"(?i)^hxxps?://", "https://", raw)
        raw = re.sub(r"(?i)^hxxp://", "http://", raw)
        try:
            host = urlsplit(raw).hostname or ""
        except ValueError:
            host = ""
        host = host.lower().rstrip(".")
        if host and re.fullmatch(r"[a-z0-9.-]{1,253}", host) and ".." not in host and host not in domains:
            domains.append(host)
    return domains[:30]


def sender_domain(value: object) -> str:
    address = parseaddr(str(value or ""))[1].strip().lower()
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[-1].rstrip(".")
    return domain if re.fullmatch(r"[a-z0-9.-]{1,253}", domain) and ".." not in domain else ""


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def content_hash(subject: str, body: str) -> str:
    normalized = {"subject": subject.casefold(), "body": re.sub(r"\s+", " ", body).strip().casefold()}
    return digest(normalized)


def legacy_hash(subject: str, body: str, sender: str = "", urls: Iterable[str] = (), flags: Iterable[str] = ()) -> str:
    """Match the Phase III pilot identity for overlap checks where possible."""
    identity = {
        "subject": subject[:300].casefold(),
        "body_excerpt": re.sub(r"\s+", " ", body[:600]).strip().casefold(),
        "sender_domain": sender,
        "reply_to_domain": "",
        "authentication_summary": [],
        "url_domains": list(urls),
        "url_structural_flags": list(flags),
        "attachment_metadata": "",
    }
    return digest(identity)


def safe_placeholder(prefix: str, value: object) -> str:
    return f"{prefix}-{hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:16]}"


def normalize_authentication(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    allowed = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
    result: list[str] = []
    for key in ("spf", "dkim", "dmarc"):
        status = str(value.get(key, "")).strip().lower()
        if status in allowed:
            result.append(f"{key}={status}")
    return result


def normalize_attachment(tokens: object, mime_types: object) -> tuple[str, str]:
    token_list = tokens if isinstance(tokens, list) else []
    mime_list = mime_types if isinstance(mime_types, list) else []
    extension = ".pdf" if "<ATTACHMENT_PDF>" in token_list else ""
    attachment_mimes = [str(value).lower() for value in mime_list if str(value).lower() not in {"text/plain", "text/html"}]
    mime = "application/pdf" if extension else (attachment_mimes[0] if attachment_mimes else "")
    if mime and not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime):
        mime = ""
    return extension, mime


def normalize_url_groups(value: object) -> list[str]:
    values = value if isinstance(value, list) else []
    return [safe_placeholder("url-domain", item) for item in values if str(item).strip()][:30]


def campaign_features(record: dict[str, object], text: str) -> set[str]:
    evidence = {str(item) for item in record.get("automated_evidence", []) if isinstance(item, str)}
    family = str(record.get("phishing_family", ""))
    features: set[str] = set()
    if family == "credential" or evidence & {"credential_request", "login_verification_request"}:
        features.add("credential_theft")
    if family == "account_security" or "account_threat" in evidence:
        features.add("account_suspension")
    if family == "invoice_payment" or evidence & {"payment_redirection", "bec_indicator"}:
        features.add("financial_claims")
    if family == "delivery":
        features.add("delivery_scam")
    if evidence & {"government_impersonation", "legal_threat"}:
        features.add("government_legal_impersonation")
    if "brand_impersonation" in evidence:
        features.add("brand_impersonation")
    if record.get("url_domain_groups"):
        features.add("malicious_link_language")
    if "sender_domain_mismatch" in evidence:
        features.add("sender_domain_mismatch")
    if "attachment_tokens" in record and record.get("attachment_tokens"):
        features.add("attachment_related")
    lowered = text.casefold()
    keyword_groups = {
        "credential_theft": ("password", "login", "verify", "credential", "sign in"),
        "account_suspension": ("suspend", "locked", "deactivat", "disabled"),
        "financial_claims": ("invoice", "payment", "refund", "bank", "transaction", "claim"),
        "delivery_scam": ("package", "parcel", "delivery", "shipment", "tracking", "customs"),
        "government_legal_impersonation": ("government", "court", "legal", "fine", "lawsuit", "tax authority"),
        "brand_impersonation": ("microsoft", "google", "paypal", "amazon", "apple", "docusign"),
        "malicious_link_language": ("click", "link", "visit", "open"),
    }
    for feature, words in keyword_groups.items():
        if any(word in lowered for word in words):
            features.add(feature)
    return features


@dataclass
class Candidate:
    source_dataset: str
    label: str
    campaign_id: str
    language: str
    subject: str
    body_excerpt: str
    sender_domain: str = ""
    reply_to_domain: str = ""
    authentication_summary: list[str] = field(default_factory=list)
    url_domains: list[str] = field(default_factory=list)
    url_structural_flags: list[str] = field(default_factory=list)
    attachment_extension: str = ""
    attachment_mime: str = ""
    source_record_key: str = ""
    template_id: str = ""
    brand_id: str = ""
    features: set[str] = field(default_factory=set)
    source_row: int = 0
    content_hash: str = ""
    legacy_content_hash: str = ""

    def finalize(self) -> "Candidate | None":
        self.subject = sanitize_text(self.subject, 300)
        self.body_excerpt = sanitize_text(self.body_excerpt, 800)
        if not self.subject and not self.body_excerpt:
            return None
        if len(self.body_excerpt) < 20 and len(self.subject) < 12:
            return None
        self.language = self.language or "und"
        self.content_hash = content_hash(self.subject, self.body_excerpt)
        self.legacy_content_hash = legacy_hash(self.subject, self.body_excerpt, self.sender_domain, self.url_domains, self.url_structural_flags)
        self.source_sample_id = f"{'safe' if self.label == 'safe' else 'phish'}-{self.content_hash[:16]}"  # type: ignore[attr-defined]
        return self

    @property
    def source_sample_id(self) -> str:  # type: ignore[override]
        return getattr(self, "_source_sample_id", "")

    @source_sample_id.setter
    def source_sample_id(self, value: str) -> None:  # type: ignore[override]
        self._source_sample_id = value

    @property
    def normalized_text(self) -> str:
        return re.sub(r"\W+", " ", f"{self.subject} {self.body_excerpt}".casefold()).strip()

    def to_row(self) -> dict[str, str]:
        sample_hash = digest({"normalized_content_hash": self.content_hash, "source_sample_id": self.source_sample_id})
        return {
            "source_sample_id": self.source_sample_id,
            "source_dataset": self.source_dataset,
            "source_claimed_label": self.label,
            "campaign_id": self.campaign_id,
            "language": self.language,
            "subject": self.subject,
            "body_excerpt": self.body_excerpt,
            "sender_domain": self.sender_domain,
            "reply_to_domain": self.reply_to_domain,
            "authentication_summary": ";".join(self.authentication_summary),
            "url_domains": ";".join(self.url_domains),
            "url_structural_flags": ";".join(self.url_structural_flags),
            "attachment_extension": self.attachment_extension,
            "attachment_mime": self.attachment_mime,
            "normalized_content_hash": self.content_hash,
            "sample_hash": sample_hash,
        }


def stable_key(candidate: Candidate, seed: str) -> tuple[str, str, int]:
    return (digest(f"{seed}|{candidate.content_hash}|{candidate.source_record_key}"), candidate.content_hash, candidate.source_row)


def load_exclusion_sets(root: Path, previous_paths: Iterable[Path], gold_db: Path) -> tuple[set[str], set[str], set[str]]:
    hashes: set[str] = set()
    legacy_hashes: set[str] = set()
    sample_ids: set[str] = set()
    for path in previous_paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                sample_ids.add(row.get("source_sample_id", ""))
                for key in ("normalized_content_hash", "sample_hash"):
                    value = row.get(key, "").strip().lower()
                    if re.fullmatch(r"[a-f0-9]{64}", value):
                        hashes.add(value)
                subject = sanitize_text(row.get("subject", ""), 300)
                body = sanitize_text(row.get("body_excerpt", ""), 600)
                legacy_hashes.add(legacy_hash(subject, body, row.get("sender_domain", ""), [], []))
    if gold_db.exists():
        connection = sqlite3.connect(gold_db)
        for table, columns in (("gold_reviews", ("sample_hash", "normalized_content_hash")), ("dataset_review_items", ("sample_hash", "normalized_content_hash"))):
            try:
                for row in connection.execute(f"SELECT {columns[0]}, {columns[1]} FROM {table}"):
                    for value in row:
                        if value:
                            hashes.add(str(value).strip().lower().removeprefix("sha256:"))
            except sqlite3.Error:
                pass
        connection.close()
    return hashes, legacy_hashes, sample_ids


def candidate_is_excluded(candidate: Candidate, excluded_hashes: set[str], legacy_hashes: set[str], sample_ids: set[str]) -> str | None:
    if candidate.source_sample_id in sample_ids:
        return "existing_sample_id"
    if candidate.content_hash in excluded_hashes:
        return "existing_normalized_content_hash"
    if candidate.legacy_content_hash in excluded_hashes or candidate.legacy_content_hash in legacy_hashes:
        return "previous_or_existing_content_overlap"
    return None


def same_or_near_duplicate(candidate: Candidate, selected: list[Candidate]) -> bool:
    if any(candidate.content_hash == item.content_hash for item in selected):
        return True
    for item in selected:
        if candidate.label != item.label:
            continue
        ratio = difflib.SequenceMatcher(None, candidate.normalized_text, item.normalized_text).quick_ratio()
        # Keep the near-duplicate guard conservative: source boilerplate can
        # be similar without being the same campaign, while 0.98 still
        # rejects essentially identical sanitized previews.
        if ratio >= 0.98:
            return True
    return False


def read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"JSONL row {line_number} is not an object")
            rows.append(value)
    return rows


def make_safe_candidates(path: Path, dataset: str, source_kind: str) -> tuple[list[Candidate], Counter[str], int]:
    candidates: list[Candidate] = []
    rejects: Counter[str] = Counter()
    if source_kind == "contextual":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        scanned = len(rows)
        for row_number, row in enumerate(rows, start=2):
            if row.get("label") != "0":
                rejects["not_safe_label"] += 1
                continue
            if row.get("language", "").lower() != "english":
                rejects["not_english"] += 1
                continue
            if row.get("spam_indicator") != "0":
                rejects["spam_indicator"] += 1
                continue
            category = row.get("category", "").lower()
            if category not in SAFE_CATEGORIES:
                rejects["ambiguous_or_marketing_category"] += 1
                continue
            candidate = Candidate(
                source_dataset=dataset,
                label="safe",
                campaign_id=f"safe-{category}",
                language="en",
                subject=row.get("subject", ""),
                body_excerpt=row.get("body", ""),
                sender_domain=sender_domain(row.get("sender", "")),
                source_record_key=str(row.get("email_id", row_number)),
                source_row=row_number,
            )
            if candidate.finalize() is None:
                rejects["missing_usable_content"] += 1
                continue
            candidates.append(candidate)
        return candidates, rejects, scanned

    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    scanned = len(rows)
    for row_number, row in enumerate(rows, start=2):
        if row.get("Email Type") != "Safe Email":
            rejects["not_safe_label"] += 1
            continue
        raw = row.get("Email Text", "")
        subject_match = re.search(r"(?im)^subject:\s*(.*?)\s*$", raw)
        subject = subject_match.group(1) if subject_match else "Safe email message"
        body = HEADER_LINE_RE.sub(" ", raw)
        candidate = Candidate(
            source_dataset=dataset,
            label="safe",
            campaign_id="safe-validation-safe",
            language="en",
            subject=subject,
            body_excerpt=body,
            source_record_key=str(row_number),
            source_row=row_number,
        )
        if candidate.finalize() is None:
            rejects["missing_usable_content"] += 1
            continue
        candidates.append(candidate)
    return candidates, rejects, scanned


def make_phishing_pot_candidates(path: Path, metadata_path: Path, dataset: str) -> tuple[list[Candidate], Counter[str], int]:
    rows = read_jsonl(path)
    source_metadata = {str(item.get("candidate_id")): item for item in read_jsonl(metadata_path)}
    candidates: list[Candidate] = []
    rejects: Counter[str] = Counter()
    for row_number, row in enumerate(rows, start=1):
        metadata = source_metadata.get(str(row.get("sample_id")), {})
        merged = {**metadata, **row}
        if row.get("label") != "phishing":
            rejects["not_phishing_label"] += 1
            continue
        if metadata.get("language") != "en":
            rejects["not_english"] += 1
            continue
        if row.get("privacy_status") != "privacy_sanitized":
            rejects["privacy_not_pass"] += 1
            continue
        if row.get("review_status") != "not_manually_reviewed":
            rejects["already_reviewed"] += 1
            continue
        subject = str(row.get("sanitized_subject") or "Phishing message")
        body = str(row.get("sanitized_visible_text") or row.get("text") or "")
        url_domains = normalize_url_groups(row.get("url_domain_groups"))
        evidence = {str(item) for item in row.get("automated_evidence", []) if isinstance(item, str)}
        flags = ["sender_domain_mismatch"] if "sender_domain_mismatch" in evidence else []
        extension, mime = normalize_attachment(row.get("attachment_tokens"), row.get("mime_type_categories"))
        auth = normalize_authentication(row.get("authentication_summary"))
        sender_group = str(row.get("sender_domain_group") or "")
        sender = safe_placeholder("sender-domain", sender_group) if sender_group and "unknown" not in sender_group else ""
        candidate = Candidate(
            source_dataset=dataset,
            label="phishing",
            campaign_id=str(merged.get("campaign_group") or "phish-campaign-undetermined"),
            language="en",
            subject=subject,
            body_excerpt=body,
            sender_domain=sender,
            authentication_summary=auth,
            url_domains=url_domains,
            url_structural_flags=flags,
            attachment_extension=extension,
            attachment_mime=mime,
            source_record_key=str(row.get("sample_id") or row_number),
            template_id=str(merged.get("template_group") or ""),
            brand_id=str(merged.get("brand_group") or "brand-unknown"),
            features=campaign_features(merged, f"{subject} {body}"),
            source_row=row_number,
        )
        if candidate.finalize() is None:
            rejects["missing_usable_content"] += 1
            continue
        candidates.append(candidate)
    return candidates, rejects, len(rows)


def make_zenodo_candidates(path: Path, dataset: str) -> tuple[list[Candidate], Counter[str], int]:
    rows = read_jsonl(path)
    candidates: list[Candidate] = []
    rejects: Counter[str] = Counter()
    for row_number, row in enumerate(rows, start=1):
        if str(row.get("label")) != "1":
            rejects["not_phishing_label"] += 1
            continue
        raw = str(row.get("text") or "")
        if not raw.strip():
            rejects["missing_usable_content"] += 1
            continue
        subject_match = re.search(r"(?im)^subject:\s*(.*?)\s*$", raw)
        subject = subject_match.group(1) if subject_match else "Phishing message"
        body = HEADER_LINE_RE.sub(" ", raw)
        candidate = Candidate(
            source_dataset=dataset,
            label="phishing",
            campaign_id="phish-zenodo-unassigned",
            language="en",
            subject=subject,
            body_excerpt=body,
            source_record_key=f"row-{row_number}",
            template_id="zenodo-unassigned",
            features=campaign_features({}, f"{subject} {body}"),
            source_row=row_number,
        )
        if candidate.finalize() is None:
            rejects["missing_usable_content"] += 1
            continue
        candidates.append(candidate)
    return candidates, rejects, len(rows)


def select_safe(candidates: list[Candidate], target: int, source_targets: dict[str, int], excluded_hashes: set[str], legacy_hashes: set[str], sample_ids: set[str], seed: str) -> tuple[list[Candidate], Counter[str]]:
    selected: list[Candidate] = []
    rejects: Counter[str] = Counter()
    by_source: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        reason = candidate_is_excluded(candidate, excluded_hashes, legacy_hashes, sample_ids)
        if reason:
            rejects[reason] += 1
        else:
            by_source[candidate.source_dataset].append(candidate)
    for source, quota in source_targets.items():
        ordered = sorted(by_source[source], key=lambda item: stable_key(item, seed))
        for candidate in ordered:
            if sum(item.source_dataset == source for item in selected) >= quota:
                break
            if same_or_near_duplicate(candidate, selected):
                rejects["duplicate_normalized_or_near_duplicate"] += 1
                continue
            selected.append(candidate)
    if len(selected) < target:
        all_remaining = sorted((item for values in by_source.values() for item in values if item not in selected), key=lambda item: stable_key(item, seed))
        for candidate in all_remaining:
            if len(selected) >= target:
                break
            if same_or_near_duplicate(candidate, selected):
                rejects["duplicate_normalized_or_near_duplicate"] += 1
                continue
            selected.append(candidate)
    if len(selected) != target:
        raise RuntimeError(f"safe selection produced {len(selected)} rows, expected {target}")
    return sorted(selected, key=lambda item: stable_key(item, seed)), rejects


def phishing_candidate_score(candidate: Candidate, selected: list[Candidate]) -> int:
    score = 0
    selected_features = {feature for item in selected for feature in item.features}
    for feature in {"credential_theft", "account_suspension", "financial_claims", "delivery_scam", "government_legal_impersonation", "brand_impersonation"}:
        if feature not in selected_features and feature in candidate.features:
            score += 100
    for feature, minimum in (("malicious_link_language", 15), ("sender_domain_mismatch", 5), ("attachment_related", 3)):
        present = sum(bool(item.url_domains) for item in selected) if feature == "malicious_link_language" else sum(feature in item.features for item in selected)
        candidate_has_feature = bool(candidate.url_domains) if feature == "malicious_link_language" else feature in candidate.features
        if present < minimum and candidate_has_feature:
            score += {"malicious_link_language": 1000, "sender_domain_mismatch": 500, "attachment_related": 400}[feature]
    if candidate.authentication_summary and not any(item.authentication_summary for item in selected):
        score += 40
    if candidate.campaign_id not in {item.campaign_id for item in selected}:
        score += 20
    if candidate.brand_id and candidate.brand_id not in {"brand-unknown", "brand-unknown-d63ef5407793"} and candidate.brand_id not in {item.brand_id for item in selected}:
        score += 5
    return score


def select_phishing(pot: list[Candidate], zenodo: list[Candidate], target: int, pot_target: int, excluded_hashes: set[str], legacy_hashes: set[str], sample_ids: set[str], seed: str) -> tuple[list[Candidate], Counter[str]]:
    selected: list[Candidate] = []
    rejects: Counter[str] = Counter()
    eligible_pot: list[Candidate] = []
    for candidate in pot:
        reason = candidate_is_excluded(candidate, excluded_hashes, legacy_hashes, sample_ids)
        if reason:
            rejects[reason] += 1
        else:
            eligible_pot.append(candidate)
    remaining = sorted(eligible_pot, key=lambda item: stable_key(item, seed))
    while len(selected) < pot_target and remaining:
        ranked = sorted(remaining, key=lambda item: (-phishing_candidate_score(item, selected), stable_key(item, seed)))
        chosen: Candidate | None = None
        for candidate in ranked:
            if sum(item.campaign_id == candidate.campaign_id for item in selected) >= 5:
                rejects["campaign_concentration_limit"] += 1
                continue
            if candidate.template_id and sum(item.template_id == candidate.template_id for item in selected) >= 1:
                rejects["template_concentration_limit"] += 1
                continue
            if candidate.brand_id not in {"", "brand-unknown", "brand-unknown-d63ef5407793"} and sum(item.brand_id == candidate.brand_id for item in selected) >= 5:
                rejects["brand_concentration_limit"] += 1
                continue
            if same_or_near_duplicate(candidate, selected):
                rejects["duplicate_normalized_or_near_duplicate"] += 1
                continue
            chosen = candidate
            break
        if chosen is None:
            break
        selected.append(chosen)
        remaining.remove(chosen)
    if len(selected) != pot_target:
        raise RuntimeError(f"Phishing Pot selection produced {len(selected)} rows, expected {pot_target}")

    eligible_zenodo: list[Candidate] = []
    for candidate in zenodo:
        reason = candidate_is_excluded(candidate, excluded_hashes, legacy_hashes, sample_ids)
        if reason:
            rejects[reason] += 1
        else:
            eligible_zenodo.append(candidate)
    for candidate in sorted(eligible_zenodo, key=lambda item: stable_key(item, seed)):
        if len(selected) >= target:
            break
        if sum(item.campaign_id == candidate.campaign_id for item in selected) >= 5:
            rejects["campaign_concentration_limit"] += 1
            continue
        if same_or_near_duplicate(candidate, selected):
            rejects["duplicate_normalized_or_near_duplicate"] += 1
            continue
        selected.append(candidate)
    if len(selected) != target:
        raise RuntimeError(f"Phishing selection produced {len(selected)} rows, expected {target}")
    return sorted(selected, key=lambda item: stable_key(item, seed)), rejects


def write_csv(path: Path, candidates: list[Candidate]) -> list[dict[str, str]]:
    rows = [candidate.to_row() for candidate in candidates]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADERS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def validate_rows(rows: list[dict[str, str]], expected_label: str) -> dict[str, object]:
    ids = [row["source_sample_id"] for row in rows]
    hashes = [row["normalized_content_hash"] for row in rows]
    sample_hashes = [row["sample_hash"] for row in rows]
    privacy: list[str] = []
    for row in rows:
        for field, value in row.items():
            if field in {"normalized_content_hash", "sample_hash", "url_domains"}:
                continue
            if EMAIL_RE.search(value):
                privacy.append("full_email_address")
            if FULL_URL_OUTPUT_RE.search(value) or QUERY_RE.search(value):
                privacy.append("full_url_or_query_string")
            if RAW_HEADER_OUTPUT_RE.search(value):
                privacy.append("raw_header")
            if HTML_TAG_RE.search(value):
                privacy.append("html_or_attachment_content")
            if ABSOLUTE_PATH_RE.search(value):
                privacy.append("absolute_path")
    for row in rows:
        for value in row["url_domains"].split(";") if row["url_domains"] else []:
            if "://" in value or "/" in value or "?" in value or "#" in value:
                privacy.append("unsafe_url_domain")
    return {
        "row_count": len(rows),
        "header_exact": list(rows[0].keys()) == HEADERS if rows else False,
        "source_sample_id_unique": len(ids) == len(set(ids)),
        "normalized_content_hash_unique": len(hashes) == len(set(hashes)),
        "sample_hash_unique": len(sample_hashes) == len(set(sample_hashes)),
        "source_claimed_label_distribution": dict(Counter(row["source_claimed_label"] for row in rows)),
        "expected_label_only": all(row["source_claimed_label"] == expected_label for row in rows),
        "privacy_violations": sorted(set(privacy)),
    }


def metadata_coverage(rows: list[dict[str, str]]) -> dict[str, float]:
    total = len(rows) or 1
    return {
        "sender_domain_present": round(sum(bool(row["sender_domain"]) for row in rows) / total, 4),
        "reply_to_domain_present": round(sum(bool(row["reply_to_domain"]) for row in rows) / total, 4),
        "authentication_summary_present": round(sum(bool(row["authentication_summary"]) for row in rows) / total, 4),
        "url_domains_present": round(sum(bool(row["url_domains"]) for row in rows) / total, 4),
        "url_structural_flags_present": round(sum(bool(row["url_structural_flags"]) for row in rows) / total, 4),
        "attachment_metadata_present": round(sum(bool(row["attachment_extension"] or row["attachment_mime"]) for row in rows) / total, 4),
        "campaign_id_present": round(sum(bool(row["campaign_id"]) for row in rows) / total, 4),
        "language_present": round(sum(bool(row["language"]) for row in rows) / total, 4),
    }


def run_importer_dry_run(root: Path, out_dir: Path, rows_by_name: dict[str, list[dict[str, str]]]) -> dict[str, object]:
    """Use the backend manager with a temporary pending-only private DB."""
    api_root = root / "apps" / "api"
    sys.path.insert(0, str(api_root))
    try:
        from app.schemas.gold_dataset import BatchImportFormat, BatchImportRequest
        from app.services.gold_dataset_manager import GoldDatasetManager
    except Exception as error:  # pragma: no cover - environment-specific diagnostic
        return {"status": "unavailable", "error": type(error).__name__, "message": str(error)[:200]}
    temp_path = out_dir / ".rich_metadata_dry_run.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{temp_path}{suffix}")
        if candidate.exists():
            candidate.unlink()
    result: dict[str, object] = {"status": "passed", "batches": {}, "gold_approvals_created": 0, "audit_approval_records_created": 0}
    manager = None
    try:
        manager = GoldDatasetManager(temp_path)
        for name, rows in rows_by_name.items():
            buffer = __import__("io").StringIO()
            writer = csv.DictWriter(buffer, fieldnames=HEADERS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            batch = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=buffer.getvalue(), imported_by="phase-ivb-dry-run", batch_id=f"dry-run-{name}-v1"))
            result["batches"][name] = {"imported": batch.imported_count, "duplicates": batch.duplicate_count, "pending_items": sum(item.state.value == "pending" for item in batch.items), "malformed_rows": 0}
        connection = sqlite3.connect(temp_path)
        result["gold_approvals_created"] = connection.execute("SELECT COUNT(*) FROM gold_reviews WHERE state='approved'").fetchone()[0]
        result["audit_approval_records_created"] = connection.execute("SELECT COUNT(*) FROM gold_review_audit WHERE new_state='approved'").fetchone()[0]
        connection.close()
    except Exception as error:
        result = {"status": "failed", "error": type(error).__name__, "message": str(error)[:240]}
    finally:
        # CPython normally releases the sqlite handle at close; collect the
        # manager as well because Windows keeps the temporary file locked
        # while any connection wrapper is still reachable.
        import gc

        if manager is not None:
            del manager
        gc.collect()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{temp_path}{suffix}")
            if candidate.exists():
                candidate.unlink()
    return result


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def write_report(path: Path, manifest: dict[str, object], source_notes: list[str]) -> None:
    coverage = manifest["metadata_coverage"]
    lines = [
        "# Phase IV.B rich-metadata pilot candidate selection",
        "",
        "This report describes private, unapproved review candidates. Source labels are advisory provenance only.",
        "",
        "## 1. Sources inspected",
        "",
        *[f"- `{note}`" for note in source_notes],
        "",
        "## 2. Candidates scanned",
        "",
        *[f"- `{name}`: {details['scanned_rows']} rows scanned; {details['eligible_rows_before_duplicate_filter']} usable candidates before overlap and selection filters." for name, details in manifest["sources"].items()],
        "",
        "## 3. Selection method",
        "",
        "Deterministic SHA-256 ordering with a fixed seed, explicit safe/phishing source quotas, usable-content filtering, source-label filtering, existing-approved/prior-pilot overlap exclusion, exact normalized-content hashes, high-similarity text rejection, and campaign/template/brand concentration limits. Phishing Pot campaign/template identifiers are retained only as existing pseudonymous group IDs; Zenodo rows are marked as an unassigned campaign because no campaign evidence is present.",
        "",
        "## 4. Source and campaign diversity",
        "",
        f"- Class distribution: `{manifest['class_distribution']}`",
        f"- Source distribution: `{manifest['source_distribution']}`",
        f"- Campaign distribution uses pseudonymous/synthetic IDs only: `{manifest['campaign_distribution']}`",
        "",
        "## 5. Metadata coverage",
        "",
        *[f"- {key}: {value:.1%}" for key, value in coverage.items()],
        "",
        f"Per-class coverage: `{manifest['metadata_coverage_by_class']}`",
        "",
        "Rich phishing metadata is concentrated in the privacy-sanitized Phishing Pot derived records. Safe sources do not retain sender authentication, reply-to, or URL evidence; those fields remain blank rather than inferred.",
        "",
        "## 6. Duplicate removal and exclusions",
        "",
        f"- Exclusion counts: `{manifest['exclusion_counts']}`",
        f"- Duplicate/concentration removal counts: `{manifest['duplicate_removal_counts']}`",
        "- Existing approved records, prior pilot rows, and all records already present in the local review queue were treated as overlap exclusions.",
        "",
        "## 7. Privacy sanitization",
        "",
        "Subjects and short body excerpts were reduced to plain text. Full email addresses, URLs, URL query strings, raw headers, HTML markup, local paths, token-like values, attachment contents, and filenames were not exported. Sender/reply-to data is blank when unavailable; pseudonymous domain placeholders are used only where the source already retained hashed domain-group evidence. Attachment output is limited to extension and MIME type.",
        "",
        "## 8. Unmet targets and questionable exclusions",
        "",
        *[f"- {item}" for item in manifest["unmet_targets"]],
        "- Policy-blocked ham corpora were not used. Phishing Pot remains staging-only and not development-approved. External Zenodo safe rows are retained only as review candidates and must not be promoted to training.",
        "",
        "## 9. Import and human review instructions",
        "",
        "The importer dry run is pending/recorded in the manifest and creates only temporary pending queue rows. It creates no approvals, human labels, or approval audit records.",
        "",
        "Safe batch:",
        "1. Import `rich_safe_review_batch_25.csv`.",
        "2. Filter duplicates/errors.",
        "3. Review every sanitized preview.",
        "4. Select only clearly legitimate records.",
        "5. Mark Safe and set confidence based on evidence.",
        "6. Approve only verified records.",
        "",
        "Phishing batch:",
        "1. Import `rich_phishing_review_batch_25.csv`.",
        "2. Review every preview and metadata field.",
        "3. Select only clearly phishing records.",
        "4. Mark Phishing and require a second review for ambiguous/high-impact cases.",
        "5. Approve only verified records; do not approve the batch blindly.",
        "",
        "## 10. Post-review plan",
        "",
        "After human approval, compare the original 75-record approved set, the expanded approved set, the metadata-rich subset, and the original false-negative cohort across recall, precision, F1, false negatives, false positives, metadata coverage, source/campaign diversity, calibration, and with/without metadata-rich records. No model change is part of this phase.",
        "",
        "Source labels remain advisory only. No human labels or gold approvals were created by this preparation.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(root: Path, out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_contextual = root / "services/ml/data/external/contextual_email_deception_cc0.csv"
    safe_validation = root / "services/ml/data/external/Phishing_validation_emails.csv"
    phish_pot = root / "services/ml/data/interim/phishing_pot_batch_002/sanitized_derived_records.jsonl"
    phish_pot_metadata = root / "services/ml/data/external/phishing_pot/metadata/source_metadata.jsonl"
    phish_zenodo = root / "services/ml/data/interim/core_candidates.jsonl"
    previous_safe = root / "services/ml/evaluation/private/dataset_review_pilot/safe_review_batch_50.csv"
    previous_phish = root / "services/ml/evaluation/private/dataset_review_pilot/phishing_review_batch_50.csv"
    gold_db = root / "services/ml/evaluation/private/review_workspace.sqlite3"

    excluded_hashes, legacy_hashes, sample_ids = load_exclusion_sets(root, (previous_safe, previous_phish), gold_db)
    safe_a, safe_a_rejects, safe_a_scanned = make_safe_candidates(safe_contextual, "kaggle_contextual_email_deception_cc0", "contextual")
    safe_b, safe_b_rejects, safe_b_scanned = make_safe_candidates(safe_validation, "zenodo_phishing_validation_13474746", "validation")
    pot, pot_rejects, pot_scanned = make_phishing_pot_candidates(phish_pot, phish_pot_metadata, "github_rf_peixoto_phishing_pot")
    zenodo, zenodo_rejects, zenodo_scanned = make_zenodo_candidates(phish_zenodo, "zenodo_phishing_nlp_15235123")

    # The prior safe pilot consumed nearly all unique non-marketing Kaggle
    # identities; retain a five-row contribution for source diversity and use
    # the separate labeled-safe validation source for the balance.
    safe_selected, safe_selection_rejects = select_safe(safe_a + safe_b, TARGET_SAFE, {"kaggle_contextual_email_deception_cc0": 5, "zenodo_phishing_validation_13474746": 20}, excluded_hashes, legacy_hashes, sample_ids, "phase-ivb-safe-v1")
    phish_selected, phish_selection_rejects = select_phishing(pot, zenodo, TARGET_PHISHING, 20, excluded_hashes, legacy_hashes, sample_ids, "phase-ivb-phishing-v1")
    safe_rows = write_csv(out_dir / "rich_safe_review_batch_25.csv", safe_selected)
    phish_rows = write_csv(out_dir / "rich_phishing_review_batch_25.csv", phish_selected)
    safe_validation_result = validate_rows(safe_rows, "safe")
    phish_validation_result = validate_rows(phish_rows, "phishing")
    if safe_validation_result["privacy_violations"] or phish_validation_result["privacy_violations"]:
        raise RuntimeError({"safe": safe_validation_result, "phishing": phish_validation_result})

    all_rows = safe_rows + phish_rows
    coverage = metadata_coverage(all_rows)
    unmet_targets = [
        "Safe URL-domain evidence target (10/25) is unmet: the selected legitimate source formats retain no URL evidence.",
        "Safe explicit authentication target (10/25) is unmet: neither legitimate source retains explicit SPF/DKIM/DMARC evidence.",
        "Overall sender-domain coverage target (80%) is unmet because the external safe validation source has no sender field and only five new safe rows could be taken from the remaining unique Kaggle pool.",
        "Safe source diversity is represented by two sources, but only one unique non-overlapping Kaggle identity remained; the other 24 safe candidates come from the labeled-safe external validation source.",
        "Safe matching sender/link-domain target (5) is unmet because safe URL evidence is unavailable.",
        "Reply-to-domain target is unmet: the available rich source retains reply-to relationship status but not a privacy-safe reply-to domain value.",
        "Government/legal impersonation coverage is source-dependent; only retain it if the final selected sanitized previews contain clear evidence and otherwise report the gap during review.",
    ]
    sources = {
        "kaggle_contextual_email_deception_cc0": {"input": "services/ml/data/external/contextual_email_deception_cc0.csv", "scanned_rows": safe_a_scanned, "eligible_rows_before_duplicate_filter": len(safe_a), "selected_rows": sum(row["source_dataset"] == "kaggle_contextual_email_deception_cc0" for row in safe_rows), "rejections": dict(safe_a_rejects)},
        "zenodo_phishing_validation_13474746": {"input": "services/ml/data/external/Phishing_validation_emails.csv", "scanned_rows": safe_b_scanned, "eligible_rows_before_duplicate_filter": len(safe_b), "selected_rows": sum(row["source_dataset"] == "zenodo_phishing_validation_13474746" for row in safe_rows), "rejections": dict(safe_b_rejects)},
        "github_rf_peixoto_phishing_pot": {"input": "services/ml/data/interim/phishing_pot_batch_002/sanitized_derived_records.jsonl", "scanned_rows": pot_scanned, "eligible_rows_before_duplicate_filter": len(pot), "selected_rows": sum(row["source_dataset"] == "github_rf_peixoto_phishing_pot" for row in phish_rows), "rejections": dict(pot_rejects)},
        "zenodo_phishing_nlp_15235123": {"input": "services/ml/data/interim/core_candidates.jsonl", "scanned_rows": zenodo_scanned, "eligible_rows_before_duplicate_filter": len(zenodo), "selected_rows": sum(row["source_dataset"] == "zenodo_phishing_nlp_15235123" for row in phish_rows), "rejections": dict(zenodo_rejects)},
    }
    exclusion_counts = Counter({"known_overlap_hash_values_loaded": len(excluded_hashes), "candidate_filter_rejections": sum([*safe_a_rejects.values(), *safe_b_rejects.values(), *pot_rejects.values(), *zenodo_rejects.values()])})
    duplicate_removal = Counter()
    duplicate_removal.update(safe_selection_rejects)
    duplicate_removal.update(phish_selection_rejects)
    manifest: dict[str, object] = {
        "script_version": SCRIPT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_files": {
            "safe": "rich_safe_review_batch_25.csv",
            "phishing": "rich_phishing_review_batch_25.csv",
            "report": "candidate_selection_report.md",
        },
        "headers": HEADERS,
        "row_counts": {"safe": len(safe_rows), "phishing": len(phish_rows), "total": len(all_rows)},
        "sources": sources,
        "class_distribution": dict(Counter(row["source_claimed_label"] for row in all_rows)),
        "source_distribution": dict(Counter(row["source_dataset"] for row in all_rows)),
        "campaign_distribution": dict(Counter(row["campaign_id"] for row in all_rows)),
        "language_distribution": dict(Counter(row["language"] for row in all_rows)),
        "metadata_coverage": coverage,
        "metadata_coverage_by_class": {"safe": metadata_coverage(safe_rows), "phishing": metadata_coverage(phish_rows)},
        "exclusion_counts": dict(exclusion_counts),
        "duplicate_removal_counts": dict(duplicate_removal),
        "selection_validation": {"safe": safe_validation_result, "phishing": phish_validation_result},
        "unmet_targets": unmet_targets,
        "privacy": {"full_email_addresses": False, "full_urls": False, "url_queries": False, "raw_headers": False, "raw_html": False, "attachment_contents": False, "absolute_paths": False, "secrets": False, "source_ids_synthetic": True},
        "human_review_boundary": {"source_claimed_label_is_advisory": True, "final_human_label_populated": False, "adjudicated_label_populated": False, "approvals_created": 0, "audit_approval_records_created": 0, "gemini_called": False, "source_datasets_modified": False, "models_or_thresholds_modified": False},
    }
    manifest["dry_run_import"] = run_importer_dry_run(root, out_dir, {"safe": safe_rows, "phishing": phish_rows})
    (out_dir / "rich_metadata_pilot_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["file_sha256"] = {name: sha256_file(out_dir / name) for name in ("rich_safe_review_batch_25.csv", "rich_phishing_review_batch_25.csv")}
    (out_dir / "rich_metadata_pilot_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    source_notes = [f"{name} ({details['input']}; registry/policy status audited locally)" for name, details in sources.items()]
    source_notes.extend([
        "services/ml/config/dataset_source_registry.json (source approval, privacy, license, split, and staging policy)",
        "services/ml/evaluation/private/dataset_review_pilot/pilot_manifest.json (previous pilot overlap baseline)",
        "services/ml/evaluation/private/gold_dataset_error_analysis/false_negative_summary.json (prior error cohort and evidence-gap baseline)",
        "services/ml/evaluation/private/gold_dataset_error_analysis/false_negative_groups.csv (prior source/campaign grouping)",
        "apps/api/app/services/gemini_review_sanitizer.py and apps/api/app/services/gold_dataset_manager.py (sanitizer and importer contracts)",
    ])
    write_report(out_dir / "candidate_selection_report.md", manifest, source_notes)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3], help="Repository root")
    parser.add_argument("--output-dir", type=Path, default=None, help="Private output directory; must remain under the repository private evaluation directory")
    args = parser.parse_args()
    root = args.root.resolve()
    out_dir = (args.output_dir or root / OUT_RELATIVE).resolve()
    private_root = (root / "services/ml/evaluation/private").resolve()
    if private_root not in out_dir.parents:
        raise SystemExit("Refusing to write outside services/ml/evaluation/private")
    manifest = build(root, out_dir)
    print(json.dumps({"output_directory": str(out_dir.relative_to(root)).replace("\\", "/"), "row_counts": manifest["row_counts"], "dry_run_import": manifest["dry_run_import"], "file_sha256": manifest["file_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
