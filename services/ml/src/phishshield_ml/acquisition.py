"""Guarded dataset acquisition and local-only email parsing utilities.

This module never renders HTML, follows links found in messages, executes
attachments, or extracts attachment bodies. Network access is limited to exact
URLs in the reviewed source registry.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import tarfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

import pandas as pd

from .preprocessing import normalize_email_text


URL_PATTERN = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+|\bwww\.[^\s<>\"']+")
EMAIL_PATTERN = re.compile(r"(?i)(?<![\w.+-])([a-z0-9][a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,})(?![\w.-])")
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
MAX_MIME_PARTS = 200
MAX_MIME_DEPTH = 12
MAX_TEXT_PART_BYTES = 2 * 1024 * 1024
MAX_DECODED_TEXT_BYTES = 5 * 1024 * 1024
AUTHENTICATION_HEADERS = (
    "Authentication-Results",
    "ARC-Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
)


@dataclass(frozen=True)
class SourceRecord:
    id: str
    name: str
    official_page: str | None
    download_url: str | None
    archive_filename: str | None
    expected_checksum: str | None
    license: str
    status: str
    role: str
    original_label_meaning: str
    assigned_project_label: Any
    language_scope: str
    limitations: str
    block_reason: str | None = None


class _SafeHTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.urls: list[str] = []
        self.remote_resource_count = 0
        self.sensitive_attribute_count = 0
        self._suppressed_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "svg", "template"}:
            self._suppressed_depth += 1
        for key, value in attrs:
            if value and (EMAIL_PATTERN.search(html.unescape(value)) or _url_has_sensitive_components(value)):
                self.sensitive_attribute_count += 1
            if key.lower() in {"href", "src", "action"} and value:
                candidate = html.unescape(value).strip()
                if URL_PATTERN.match(candidate):
                    self.urls.append(candidate)
                    if key.lower() == "src":
                        self.remote_resource_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "svg", "template"} and self._suppressed_depth:
            self._suppressed_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._suppressed_depth:
            self.text_parts.append(data)


def load_source_registry(path: str | Path) -> tuple[dict[str, Any], dict[str, SourceRecord]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    records = {item["id"]: SourceRecord(**item) for item in payload["sources"]}
    return payload, records


def validate_download_source(source: SourceRecord) -> None:
    if source.status != "approved":
        reason = source.block_reason or source.status
        raise PermissionError(f"Source {source.id!r} is not approved: {reason}")
    if not source.download_url or not source.archive_filename:
        raise ValueError(f"Approved source {source.id!r} lacks a direct download")
    parsed = urllib.parse.urlparse(source.download_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Source {source.id!r} must use a direct HTTPS URL")


def compute_checksums(path: str | Path) -> dict[str, str]:
    digests = {"md5": hashlib.md5(usedforsecurity=False), "sha256": hashlib.sha256()}
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def verify_expected_checksum(path: str | Path, expected: str | None) -> dict[str, str]:
    actual = compute_checksums(path)
    if expected:
        algorithm, expected_value = expected.lower().split(":", 1)
        if algorithm not in actual:
            raise ValueError(f"Unsupported checksum algorithm: {algorithm}")
        if actual[algorithm] != expected_value:
            raise ValueError(
                f"Checksum mismatch for {Path(path).name}: expected {expected}, "
                f"got {algorithm}:{actual[algorithm]}"
            )
    return actual


def download_source(source: SourceRecord, destination_root: str | Path, *, overwrite: bool = False) -> dict[str, Any]:
    """Download one approved registry URL without using message-derived links."""
    validate_download_source(source)
    destination = Path(destination_root) / source.archive_filename  # type: ignore[arg-type]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        checksums = verify_expected_checksum(destination, source.expected_checksum)
        return _download_record(source, destination, checksums, "already_present")

    partial = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        source.download_url,  # type: ignore[arg-type]
        headers={"User-Agent": "PhishPhage-Dataset-Acquisition/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
        final_host = urllib.parse.urlparse(response.geturl()).hostname
        approved_host = urllib.parse.urlparse(source.download_url).hostname  # type: ignore[arg-type]
        if final_host != approved_host:
            raise RuntimeError(f"Unexpected cross-host redirect for {source.id}: {final_host}")
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    checksums = verify_expected_checksum(partial, source.expected_checksum)
    partial.replace(destination)
    return _download_record(source, destination, checksums, "downloaded")


def _download_record(
    source: SourceRecord, path: Path, checksums: dict[str, str], outcome: str
) -> dict[str, Any]:
    return {
        "source_id": source.id,
        "official_url": source.official_page,
        "download_url": source.download_url,
        "license": source.license,
        "download_date_utc": datetime.now(timezone.utc).date().isoformat(),
        "archive_filename": path.name,
        "bytes": path.stat().st_size,
        "checksums": checksums,
        "expected_checksum": source.expected_checksum,
        "original_label_meaning": source.original_label_meaning,
        "assigned_project_label": source.assigned_project_label,
        "role": source.role,
        "outcome": outcome,
    }


def safe_archive_members(path: str | Path) -> list[dict[str, Any]]:
    """Inspect tar members without extracting them and reject unsafe entries."""
    archive = Path(path)
    if not tarfile.is_tarfile(archive):
        return []
    members: list[dict[str, Any]] = []
    with tarfile.open(archive, mode="r:*") as handle:
        for member in handle.getmembers():
            pure = PurePosixPath(member.name.replace("\\", "/"))
            if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk():
                raise ValueError(f"Unsafe archive member: {member.name}")
            members.append({"name": member.name, "bytes": member.size, "is_file": member.isfile()})
    return members


def _decoded_part(part: Message, *, limit: int = MAX_TEXT_PART_BYTES) -> tuple[str, bool]:
    """Decode inert text with a strict byte ceiling; never invoke content handlers."""
    payload = part.get_payload(decode=True) or b""
    truncated = len(payload) > limit
    payload = payload[:limit]
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace"), truncated
    except LookupError:
        return payload.decode("utf-8", errors="replace"), truncated


def _leaf_parts(message: Message) -> Iterator[tuple[Message, int]]:
    """Walk MIME without recursion and reject part-count/depth bombs."""
    stack: list[tuple[Message, int]] = [(message, 0)]
    seen = 0
    while stack:
        part, depth = stack.pop()
        seen += 1
        if seen > MAX_MIME_PARTS:
            raise ValueError(f"Message exceeds {MAX_MIME_PARTS} MIME parts")
        if depth > MAX_MIME_DEPTH:
            raise ValueError(f"Message exceeds MIME depth {MAX_MIME_DEPTH}")
        payload = part.get_payload()
        if part.is_multipart() and isinstance(payload, list):
            stack.extend((child, depth + 1) for child in reversed(payload))
        else:
            yield part, depth


def mask_email_address(value: str) -> str:
    """Return a stable display mask without exposing the local part."""
    address = parseaddr(value)[1].lower()
    if "@" not in address:
        return ""
    local, domain = address.rsplit("@", 1)
    return f"{local[:1] or '*'}***@{domain}"


def _url_has_sensitive_components(value: str) -> bool:
    candidate = html.unescape(value).strip()
    parseable = re.sub(r"(?i)^hxxps?://", "https://", candidate)
    if parseable.lower().startswith("www."):
        parseable = "https://" + parseable
    try:
        parsed = urllib.parse.urlsplit(parseable)
    except ValueError:
        return False
    return bool(parsed.query or parsed.fragment)


def _safe_url_evidence(value: str) -> dict[str, Any]:
    candidate = value.strip().rstrip(".,);]")
    parseable = re.sub(r"(?i)^hxxps?://", "https://", candidate)
    if parseable.lower().startswith("www."):
        parseable = "https://" + parseable
    try:
        parsed = urllib.parse.urlsplit(parseable)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {
            "host": "",
            "scheme": "",
            "path_present": False,
            "query_parameter_names": [],
            "has_fragment": False,
            "malformed": True,
        }
    parameter_names = sorted({name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
    return {
        "host": host,
        "scheme": parsed.scheme.lower(),
        "path_present": bool(parsed.path and parsed.path != "/"),
        "query_parameter_names": parameter_names,
        "has_fragment": bool(parsed.fragment),
    }


def _privacy_summary(
    message: Message,
    decoded_text: str,
    urls: Iterable[str],
    *,
    sensitive_html_attribute_count: int,
    attachment_names: Iterable[str],
) -> dict[str, Any]:
    header_names = ("From", "To", "Cc", "Reply-To", "Return-Path", "Received")
    masked_headers: dict[str, list[str]] = {}
    address_locations: list[str] = []
    for name in header_names:
        matches: list[str] = []
        for value in message.get_all(name, []):
            matches.extend(EMAIL_PATTERN.findall(str(value)))
        if matches:
            address_locations.append(name.lower())
            masked_headers[name.lower()] = sorted({mask_email_address(item) for item in matches})
    body_addresses = EMAIL_PATTERN.findall(decoded_text)
    evidence = [_safe_url_evidence(url) for url in sorted(set(urls))]
    flags: list[str] = []
    if address_locations:
        flags.append("address_in_header")
    if body_addresses:
        flags.append("address_in_decoded_content")
    if any(item["query_parameter_names"] for item in evidence):
        flags.append("sensitive_url_parameters_require_review")
    attachment_privacy_count = sum(
        1 for name in attachment_names
        if EMAIL_PATTERN.search(name) or re.search(r"(?i)(?:token|secret|password|credential|account)[-_ ]", name)
    )
    if sensitive_html_attribute_count:
        flags.append("sensitive_html_attribute_requires_review")
    if attachment_privacy_count:
        flags.append("sensitive_attachment_name_requires_review")
    return {
        "flags": flags,
        "address_header_locations": sorted(address_locations),
        "decoded_content_address_count": len(set(map(str.lower, body_addresses))),
        "masked_header_addresses": masked_headers,
        "url_evidence": evidence,
        "sensitive_html_attribute_count": sensitive_html_attribute_count,
        "sensitive_attachment_name_count": attachment_privacy_count,
    }


def _domain(header_value: str | None) -> str:
    address = parseaddr(header_value or "")[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def parse_email_bytes(raw: bytes, *, source_id: str, campaign_id: str) -> dict[str, Any]:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Message exceeds {MAX_MESSAGE_BYTES} bytes")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("Message could not be parsed safely") from exc
    plain_parts: list[str] = []
    html_parts: list[str] = []
    urls: list[str] = []
    attachments: list[dict[str, Any]] = []
    mime_types: set[str] = set()
    parse_warnings = [type(defect).__name__ for defect in message.defects]
    remote_resources_blocked = 0
    sensitive_html_attribute_count = 0
    decoded_text_bytes = 0

    for part, _depth in _leaf_parts(message):
        mime_types.add(part.get_content_type().lower())
        parse_warnings.extend(type(defect).__name__ for defect in part.defects)
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        payload = part.get_payload(decode=True) or b""
        if filename or disposition == "attachment":
            safe_name = Path(filename).name if filename else null_filename()
            attachments.append(
                {
                    "filename": safe_name,
                    "privacy_safe_filename": {
                        "extension": Path(safe_name).suffix.lower(),
                        "name_sha256_prefix": hashlib.sha256(safe_name.encode("utf-8", errors="replace")).hexdigest()[:12],
                    },
                    "content_type": part.get_content_type(),
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            continue
        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            text, truncated = _decoded_part(part)
            decoded_text_bytes += len(text.encode("utf-8", errors="replace"))
            if truncated:
                parse_warnings.append("TextPartTruncated")
            plain_parts.append(text)
            urls.extend(URL_PATTERN.findall(text))
        elif content_type == "text/html":
            extractor = _SafeHTMLTextExtractor()
            decoded, truncated = _decoded_part(part)
            decoded_text_bytes += len(decoded.encode("utf-8", errors="replace"))
            if truncated:
                parse_warnings.append("TextPartTruncated")
            extractor.feed(decoded)
            extractor.close()
            text = " ".join(extractor.text_parts)
            html_parts.append(text)
            remote_resources_blocked += extractor.remote_resource_count
            sensitive_html_attribute_count += extractor.sensitive_attribute_count
            urls.extend(extractor.urls)
            urls.extend(URL_PATTERN.findall(text))
        if decoded_text_bytes > MAX_DECODED_TEXT_BYTES:
            raise ValueError(f"Message exceeds {MAX_DECODED_TEXT_BYTES} decoded text bytes")

    subject = normalize_email_text(str(message.get("Subject", "")))
    plain_body = normalize_email_text("\n".join(plain_parts))
    html_text = normalize_email_text("\n".join(html_parts))
    body = plain_body or html_text
    text = normalize_email_text(f"Subject: {subject}\n\n{body}")
    auth_headers = {
        name.lower(): [normalize_email_text(value) for value in message.get_all(name, [])]
        for name in AUTHENTICATION_HEADERS
        if message.get_all(name, [])
    }
    privacy = _privacy_summary(
        message,
        "\n".join((*plain_parts, *html_parts)),
        urls,
        sensitive_html_attribute_count=sensitive_html_attribute_count,
        attachment_names=(item["filename"] for item in attachments),
    )
    return {
        "text": text,
        "subject": subject,
        "plain_body": plain_body,
        "sanitized_html_text": html_text,
        "sender_domain": _domain(message.get("From")),
        "reply_to_domain": _domain(message.get("Reply-To")),
        "urls": sorted(set(urls)),
        "authentication_headers": auth_headers,
        "mime_types": sorted(mime_types),
        "attachments": attachments,
        "remote_resources_blocked": remote_resources_blocked,
        "privacy": privacy,
        "malformed": bool(parse_warnings),
        "parse_warnings": sorted(set(parse_warnings)),
        "source": source_id,
        "campaign_id": campaign_id,
    }


def null_filename() -> str:
    return ""


def iter_rfc822_records(path: str | Path, source_id: str) -> Iterator[dict[str, Any]]:
    """Yield locally parsed RFC822 messages from a directory or tar archive."""
    source_path = Path(path)
    if source_path.is_dir():
        for candidate in sorted(item for item in source_path.rglob("*") if item.is_file()):
            relative = candidate.relative_to(source_path)
            campaign = f"{source_id}:{relative.parts[0] if len(relative.parts) > 1 else 'root'}"
            yield parse_email_bytes(candidate.read_bytes(), source_id=source_id, campaign_id=campaign)
        return
    safe_archive_members(source_path)
    with tarfile.open(source_path, mode="r:*") as handle:
        for member in handle.getmembers():
            if not member.isfile() or member.size > MAX_MESSAGE_BYTES:
                continue
            extracted = handle.extractfile(member)
            if extracted is None:
                continue
            parts = PurePosixPath(member.name).parts
            campaign = f"{source_id}:{parts[-2] if len(parts) > 1 else 'root'}"
            yield parse_email_bytes(extracted.read(), source_id=source_id, campaign_id=campaign)


def parse_zenodo_phishing_positive(path: str | Path, source_id: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Accept only the explicit Phishing class from Zenodo 15235123."""
    frame = pd.read_excel(path)
    accepted: list[dict[str, Any]] = []
    rejected: dict[str, int] = {}
    for _, row in frame.iterrows():
        raw = str(row.get("Corpus", "")) if pd.notna(row.get("Corpus")) else ""
        supplied_label = str(row.get("Labels", row.get("Label", ""))) if pd.notna(row.get("Labels", row.get("Label", ""))) else ""
        if "\t" in raw:
            text, label = raw.rsplit("\t", 1)
        elif "\t" in supplied_label:
            continuation, label = supplied_label.rsplit("\t", 1)
            text = f"{raw} {continuation}"
        else:
            text, label = raw, supplied_label
        text = normalize_email_text(text)
        label = label.strip()
        if label != "Phishing":
            rejected[label or "malformed_or_unlabeled"] = rejected.get(label or "malformed_or_unlabeled", 0) + 1
            continue
        if not text:
            rejected["empty"] = rejected.get("empty", 0) + 1
            continue
        accepted.append(
            {
                "text": text,
                "label": 1,
                "source": source_id,
                "source_role": "core_phishing_positive",
                "campaign_id": f"{source_id}:unassigned",
                "record_format": "email_or_sms_like_text",
            }
        )
    return accepted, rejected


def parse_external_validation(path: str | Path, source_id: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    mapping = {"Safe Email": 0, "Phishing Email": 1}
    accepted: list[dict[str, Any]] = []
    rejected: dict[str, int] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            text = normalize_email_text(row.get("Email Text", ""))
            label_name = row.get("Email Type", "")
            label = mapping.get(label_name)
            if not text or label is None:
                reason = "empty" if not text else f"unknown_label:{label_name}"
                rejected[reason] = rejected.get(reason, 0) + 1
                continue
            accepted.append(
                {
                    "text": text,
                    "label": label,
                    "source": source_id,
                    "source_role": "external_validation_only",
                    "campaign_id": f"{source_id}:external",
                    "record_format": "email_text",
                }
            )
    return accepted, rejected


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> int:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_not_external_path(path: str | Path) -> None:
    parts = {part.lower() for part in Path(path).resolve().parts}
    if "external" in parts:
        raise ValueError("External-validation data is physically isolated and cannot be used as core input")
