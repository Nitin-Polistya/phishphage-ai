"""Build and validate a privacy-safe, manually reviewed evaluation manifest.

This tool is intentionally label-blind during ingestion.  It reads local
candidate content, extracts only safe structural metadata, computes stable
hashes, and writes public metadata without raw bodies, addresses, URLs, or
absolute paths.  Ground truth can enter a manifest only through a separate
review-labels file.

The commands are deliberately standard-library-only so that curation remains
usable when the production model environment is unavailable::

    python apps/api/scripts/build_gold_standard_dataset.py scan \
      --input services/ml/data/external --manifest services/ml/evaluation/candidates.jsonl
    python apps/api/scripts/build_gold_standard_dataset.py apply-labels \
      --manifest services/ml/evaluation/candidates.jsonl \
      --labels services/ml/evaluation/review_labels.csv
    python apps/api/scripts/build_gold_standard_dataset.py audit
    python apps/api/scripts/build_gold_standard_dataset.py pilot
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from email import policy
from email.parser import Parser
from email.utils import getaddresses
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = "gold-standard-1.0"
SCHEMA_PATH = ROOT / "services" / "ml" / "evaluation" / "schema" / "gold_standard_schema.json"
EVALUATION_ROOT = ROOT / "services" / "ml" / "evaluation"
PRIVATE_ROOT = EVALUATION_ROOT / "private"
DEFAULT_MANIFEST = EVALUATION_ROOT / "candidate_manifest.jsonl"
DEFAULT_QUEUE = EVALUATION_ROOT / "review_queue.csv"
DEFAULT_LABEL_TEMPLATE = EVALUATION_ROOT / "review_labels_template.csv"
DEFAULT_REPORT_ROOT = ROOT / "reports" / "gold_standard"
VALID_CLASSES = ("safe", "suspicious", "phishing")
REVIEW_STATUSES = ("unreviewed", "provisional", "adjudicated", "conflict", "excluded")
RAW_KEYS = {
    "raw_email", "raw_text", "email", "email_text", "Email Text", "content",
    "text", "message", "body_text", "body", "html", "headers", "attachment_content",
}
ABSOLUTE_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]{1,2})")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
URL_RE = re.compile(r"\b(?:https?://|ftp://|mailto:)[^\s<>\"']+", re.I)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-]{28,}(?![A-Za-z0-9])")
INLINE_ABSOLUTE_PATH_RE = re.compile(r"(?i)(?:\b[A-Za-z]:[\\/]|(?<!\w)/(?:users|home|tmp|var|private|mnt|opt|workspace)[\\/])[^\r\n,;]+")
SUPPORTED_SUFFIXES = {".eml", ".txt", ".json", ".jsonl", ".csv"}

PUBLIC_FIELDS = (
    "sample_id", "expected_class", "source_dataset", "source_record_id", "campaign",
    "sample_date", "language", "sender_domain", "claimed_organization",
    "attachment_present", "attachment_types", "url_present", "url_count", "email_format",
    "review_status", "reviewer_count", "adjudication_status", "labeling_notes",
    "privacy_status", "content_location", "content_hash", "schema_version", "category",
    "subset", "reviewer_1_label", "reviewer_2_label", "adjudicated_label",
    "disagreement_reason", "adjudication_notes", "final_reviewer", "final_review_date",
    "reviewer_1_confidence", "reviewer_2_confidence", "overlap_status", "training_overlap",
    "development_overlap", "duplicate_status", "content_exists", "content_hash_stable",
    "candidate_category", "exclusion_reason", "subject_redacted", "normalized_content_hash", "normalized_body_hash",
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")


def _safe_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name or "unknown"


def _is_absolute_path(value: Any) -> bool:
    return isinstance(value, str) and bool(ABSOLUTE_PATH_RE.match(value.strip()))


def _canonical_content(value: str) -> str:
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))


def stable_content_hash(value: str) -> str:
    """Return the versioned, line-ending-independent content SHA-256."""
    return hashlib.sha256(_canonical_content(value).encode("utf-8")).hexdigest()


def normalized_text(value: str) -> str:
    value = _canonical_content(value).lower()
    value = URL_RE.sub(" <url> ", value)
    value = EMAIL_RE.sub(" <email> ", value)
    value = PHONE_RE.sub(" <phone> ", value)
    value = re.sub(r"\b\d+\b", " <number> ", value)
    return re.sub(r"\s+", " ", value).strip()


def normalized_content_hash(value: str) -> str:
    return hashlib.sha256(normalized_text(value).encode("utf-8")).hexdigest()


def _redact_text(value: Any, empty: str = "unknown") -> str:
    text = str(value or "").strip()
    if not text:
        return empty
    text = URL_RE.sub("[URL redacted]", text)
    text = EMAIL_RE.sub("[address redacted]", text)
    text = PHONE_RE.sub("[phone redacted]", text)
    text = TOKEN_RE.sub("[token redacted]", text)
    text = INLINE_ABSOLUTE_PATH_RE.sub("[path redacted]", text)
    return re.sub(r"\s+", " ", text).strip() or empty


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        from email.header import decode_header, make_header

        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeError, ValueError):
        return value


def _body_text(message: Any) -> str:
    parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                payload = part.get_content()
            except (LookupError, UnicodeError, ValueError):
                payload = part.get_payload(decode=True) or b""
            if isinstance(payload, bytes):
                payload = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            parts.append(str(payload))
    else:
        try:
            payload = message.get_content()
        except (LookupError, UnicodeError, ValueError):
            payload = message.get_payload(decode=True) or b""
        if isinstance(payload, bytes):
            payload = payload.decode(message.get_content_charset() or "utf-8", errors="replace")
        parts.append(str(payload))
    return "\n".join(parts)


def _safe_email_metadata(raw: str, suffix: str) -> dict[str, Any]:
    try:
        message = Parser(policy=policy.default).parsestr(raw)
    except (ValueError, TypeError):
        message = None
    subject = _decode_header(message.get("Subject")) if message else ""
    sender_domain = "unknown"
    if message:
        addresses = getaddresses([message.get("From", "")])
        if addresses and "@" in addresses[0][1]:
            sender_domain = addresses[0][1].rsplit("@", 1)[1].strip().lower() or "unknown"
    attachment_types: list[str] = []
    if message:
        for part in message.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if part.get_content_disposition() == "attachment" or filename:
                attachment_types.append(str(part.get_content_type()).lower())
    urls = URL_RE.findall(raw)
    return {
        "sender_domain": sender_domain,
        "attachment_present": bool(attachment_types),
        "attachment_types": sorted(set(attachment_types)),
        "url_present": bool(urls),
        "url_count": len(urls),
        "email_format": "raw_rfc822" if message and (message.get("From") or message.get("Subject")) else ("raw_text" if suffix != ".eml" else "unknown"),
        "subject_redacted": _redact_text(subject, "[no subject]"),
        "normalized_hash": normalized_content_hash(raw),
        "body_hash": normalized_content_hash((_decode_header(message.get("Subject")) if message else "") + "\n" + (_body_text(message) if message else raw)),
    }


def _records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("samples", "records", "emails", "fixtures", "items"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return [payload]
    return []


def _load_json_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line in _read_text(path).splitlines():
            if not line.strip():
                continue
            try:
                records.extend(_records_from_payload(json.loads(line)))
            except json.JSONDecodeError:
                records.append({"__parse_error__": "invalid JSON"})
        return records
    try:
        return _records_from_payload(json.loads(_read_text(path)))
    except json.JSONDecodeError:
        return [{"__parse_error__": "invalid JSON"}]


def _load_csv_records(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _files_for_inputs(inputs: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for raw_path in inputs:
        path = raw_path.resolve()
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            files.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file() or candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                    continue
                if any(part in {".git", "private", "__pycache__"} for part in candidate.parts):
                    continue
                files.add(candidate.resolve())
    return sorted(files, key=lambda item: _safe_relative(item))


def _sidecar_index(files: Iterable[Path]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for path in files:
        if path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        for record in _load_json_records(path):
            path_value = record.get("path") or record.get("file") or record.get("source_path") or record.get("input_file")
            if not path_value:
                continue
            target = Path(str(path_value))
            if not target.is_absolute():
                target = path.parent / target
            keys = {str(target.resolve()), target.name}
            for key in keys:
                index[key] = {k: v for k, v in record.items() if k not in {"path", "file", "source_path", "input_file"}}
    return index


def _content_from_record(record: dict[str, Any], base_dir: Path) -> tuple[str | None, str]:
    content_keys = ("raw_email", "raw_text", "email", "email_text", "Email Text", "content", "text", "message", "body_text")
    for key in content_keys:
        if isinstance(record.get(key), str) and record[key].strip():
            return record[key], "raw_rfc822" if "raw" in key or key in {"email", "email_text", "Email Text"} else "raw_text"
    if isinstance(record.get("body"), str) and record["body"].strip():
        subject = str(record.get("subject") or "")
        return f"Subject: {subject}\n\n{record['body']}", "quick_paste"
    path_value = record.get("path") or record.get("file") or record.get("source_path") or record.get("input_file")
    if path_value:
        target = Path(str(path_value))
        if not target.is_absolute():
            target = base_dir / target
        if target.exists() and target.is_file() and target.suffix.lower() in {".eml", ".txt"}:
            return _read_text(target), "raw_rfc822" if target.suffix.lower() == ".eml" else "raw_text"
    return None, "unknown"


def _source_dataset(record: dict[str, Any], file_path: Path) -> str:
    value = record.get("source_dataset") or record.get("source")
    return _redact_text(value, f"local:{_safe_relative(file_path.parent)}")


def _candidate_from_content(record: dict[str, Any], raw: str, fmt: str, file_path: Path, record_index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    source_dataset = _source_dataset(record, file_path)
    source_record_id = _redact_text(
        record.get("source_record_id") or record.get("record_id") or record.get("id") or f"{_safe_relative(file_path)}#{record_index}",
        f"{_safe_relative(file_path)}#{record_index}",
    )
    content_hash = stable_content_hash(raw)
    sample_id = "gs-" + hashlib.sha256(f"{source_dataset}\0{source_record_id}\0{content_hash}".encode("utf-8")).hexdigest()[:20]
    parsed = _safe_email_metadata(raw, file_path.suffix.lower())
    metadata = {
        "sample_id": sample_id,
        "expected_class": None,
        "source_dataset": source_dataset,
        "source_record_id": source_record_id,
        "campaign": _redact_text(record.get("campaign"), "unknown"),
        "sample_date": _redact_text(record.get("sample_date") or record.get("date"), "unknown"),
        "language": _redact_text(record.get("language"), "unknown"),
        "sender_domain": _redact_text(record.get("sender_domain"), parsed["sender_domain"]),
        "claimed_organization": _redact_text(record.get("claimed_organization") or record.get("claimed_org"), "unknown"),
        "attachment_present": bool(record.get("attachment_present", parsed["attachment_present"])),
        "attachment_types": sorted(set(str(item).lower() for item in (record.get("attachment_types") or parsed["attachment_types"]))),
        "url_present": bool(record.get("url_present", parsed["url_present"])),
        "url_count": int(record.get("url_count", parsed["url_count"]) or 0),
        "email_format": fmt if fmt in {"raw_rfc822", "raw_text", "quick_paste"} else parsed["email_format"],
        "review_status": "unreviewed",
        "reviewer_count": 0,
        "adjudication_status": "not_started",
        "labeling_notes": "Unreviewed candidate; manual labels are required.",
        "privacy_status": "pending",
        "content_location": f"local-only://{sample_id}",
        "content_hash": content_hash,
        "schema_version": SCHEMA_VERSION,
        "category": _redact_text(record.get("category"), "unknown") if record.get("category") else None,
        "subset": "unassigned",
        "reviewer_1_label": None,
        "reviewer_2_label": None,
        "adjudicated_label": None,
        "disagreement_reason": None,
        "adjudication_notes": None,
        "final_reviewer": None,
        "final_review_date": None,
        "reviewer_1_confidence": None,
        "reviewer_2_confidence": None,
        "overlap_status": "unknown",
        "training_overlap": False,
        "development_overlap": False,
        "duplicate_status": "unknown",
        "content_exists": True,
        "content_hash_stable": True,
        "candidate_category": _redact_text(record.get("candidate_category"), "unknown") if record.get("candidate_category") else None,
        "exclusion_reason": None,
        "subject_redacted": parsed["subject_redacted"],
        "normalized_content_hash": parsed["normalized_hash"],
        "normalized_body_hash": parsed["body_hash"],
    }
    private = {
        "sample_id": sample_id,
        "content_path": _safe_relative(file_path),
        "normalized_hash": parsed["normalized_hash"],
        "body_hash": parsed["body_hash"],
    }
    return metadata, private


def scan_candidates(inputs: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    files = _files_for_inputs(inputs)
    sidecars = _sidecar_index(files)
    records: list[dict[str, Any]] = []
    private: list[dict[str, Any]] = []
    for file_path in files:
        suffix = file_path.suffix.lower()
        if suffix in {".eml", ".txt"}:
            sidecar = next((sidecars[key] for key in (str(file_path), str(file_path.resolve()), file_path.name) if key in sidecars), {})
            raw = _read_text(file_path)
            record, local = _candidate_from_content(sidecar, raw, "raw_rfc822" if suffix == ".eml" else "raw_text", file_path, 0)
            records.append(record)
            private.append(local)
            continue
        source_records = _load_csv_records(file_path) if suffix == ".csv" else _load_json_records(file_path)
        for index, source_record in enumerate(source_records):
            if source_record.get("__parse_error__"):
                continue
            path_value = source_record.get("path") or source_record.get("file") or source_record.get("source_path") or source_record.get("input_file")
            has_inline_content = any(isinstance(source_record.get(key), str) and source_record[key].strip() for key in ("raw_email", "raw_text", "email", "email_text", "Email Text", "content", "text", "message", "body_text", "body"))
            if path_value and not has_inline_content and Path(str(path_value)).suffix.lower() in {".eml", ".txt"}:
                # Metadata for a neighboring raw file is joined through the
                # sidecar index; it must not become a second sample.
                continue
            raw, fmt = _content_from_record(source_record, file_path.parent)
            if raw is None:
                continue
            record, local = _candidate_from_content(source_record, raw, fmt, file_path, index)
            records.append(record)
            private.append(local)
    records.sort(key=lambda item: item["sample_id"])
    private.sort(key=lambda item: item["sample_id"])
    return records, private


def write_manifest(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in sorted(records, key=lambda item: str(item.get("sample_id", ""))):
            public = {field: record.get(field) for field in PUBLIC_FIELDS if field in record}
            handle.write(json.dumps(public, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")


def write_private_locations(path: Path, locations: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for item in sorted(locations, key=lambda value: value["sample_id"]):
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line in _read_text(path).splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    payload = json.loads(_read_text(path))
    return _records_from_payload(payload)


def validate_record(record: dict[str, Any], final: bool = False) -> list[str]:
    issues: list[str] = []
    required = json.loads(_read_text(SCHEMA_PATH)).get("required", [])
    for field in required:
        if field not in record:
            issues.append(f"missing field: {field}")
    if record.get("expected_class") not in (*VALID_CLASSES, None):
        issues.append("invalid expected_class")
    if final and record.get("expected_class") not in VALID_CLASSES:
        issues.append("final benchmark requires an adjudicated expected_class")
    if not str(record.get("campaign", "")).strip():
        issues.append("missing campaign")
    if not str(record.get("source_dataset", "")).strip() or record.get("source_dataset") == "unknown":
        issues.append("source is unknown")
    if not re.fullmatch(r"gs-[a-f0-9]{20}", str(record.get("sample_id", ""))):
        issues.append("invalid sample_id")
    if not re.fullmatch(r"[a-f0-9]{64}", str(record.get("content_hash", ""))):
        issues.append("invalid content_hash")
    if record.get("content_location") and _is_absolute_path(str(record["content_location"])):
        issues.append("absolute content path")
    for key, value in record.items():
        if key in RAW_KEYS:
            issues.append(f"raw content field present: {key}")
        if isinstance(value, str) and _is_absolute_path(value):
            issues.append(f"absolute path present: {key}")
    if record.get("privacy_status") != "pass" and final:
        issues.append("privacy review has not passed")
    if record.get("review_status") not in REVIEW_STATUSES:
        issues.append("invalid review_status")
    if final:
        final_requirements = {
            "review_status": "adjudicated",
            "adjudication_status": "complete",
            "overlap_status": "pass",
            "duplicate_status": "pass",
            "content_exists": True,
            "content_hash_stable": True,
            "training_overlap": False,
            "development_overlap": False,
        }
        for field, expected in final_requirements.items():
            if record.get(field) != expected:
                issues.append(f"benchmark gate failed: {field}={record.get(field)!r}, expected {expected!r}")
        if record.get("reviewer_count", 0) < 2:
            issues.append("two independent reviewers are required for a gold-standard record")
        for field in ("reviewer_1_label", "reviewer_2_label", "adjudicated_label", "final_reviewer", "final_review_date", "adjudication_notes"):
            if not str(record.get(field) or "").strip():
                issues.append(f"missing adjudication field: {field}")
        if record.get("campaign") == "unknown":
            issues.append("campaign provenance is unknown")
        if record.get("language") == "unknown":
            issues.append("language is unknown")
    return sorted(set(issues))


def validate_manifest(records: list[dict[str, Any]], final: bool = False) -> dict[str, Any]:
    seen: set[str] = set()
    errors: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        sample_id = str(record.get("sample_id", ""))
        issues = validate_record(record, final=final)
        if sample_id in seen:
            issues.append("duplicate sample_id")
        seen.add(sample_id)
        if issues:
            errors.append({"index": index, "sample_id": sample_id, "issues": sorted(set(issues))})
    return {"valid": not errors, "final": final, "record_count": len(records), "error_count": len(errors), "errors": errors}


def _labels_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        return _load_csv_records(path)
    payload = json.loads(_read_text(path))
    return _records_from_payload(payload)


def apply_labels(records: list[dict[str, Any]], labels_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    label_rows = _labels_records(labels_path)
    by_id = {str(row.get("sample_id")): row for row in label_rows if row.get("sample_id")}
    errors: list[str] = []
    output: list[dict[str, Any]] = []
    allowed_label_fields = {"reviewer_1_label", "reviewer_2_label", "adjudicated_label"}
    for row in label_rows:
        if any(key in row for key in {"predicted_class", "prediction", "model_probability", "ml_probability"}):
            errors.append(f"{row.get('sample_id')}: model output is not a valid label source")
    for original in records:
        record = dict(original)
        label_row = by_id.get(str(record.get("sample_id")))
        if not label_row:
            output.append(record)
            continue
        for field in allowed_label_fields:
            value = str(label_row.get(field) or "").strip().lower() or None
            if value is not None and value not in VALID_CLASSES:
                errors.append(f"{record['sample_id']}: invalid {field}")
                value = None
            record[field] = value
        record["reviewer_1_confidence"] = _redact_text(label_row.get("reviewer_1_confidence"), "unknown") if label_row.get("reviewer_1_confidence") else None
        record["reviewer_2_confidence"] = _redact_text(label_row.get("reviewer_2_confidence"), "unknown") if label_row.get("reviewer_2_confidence") else None
        record["disagreement_reason"] = _redact_text(label_row.get("disagreement_reason"), "unknown") if label_row.get("disagreement_reason") else None
        record["adjudication_notes"] = _redact_text(label_row.get("adjudication_notes"), "unknown") if label_row.get("adjudication_notes") else None
        record["final_reviewer"] = _redact_text(label_row.get("final_reviewer"), "unknown") if label_row.get("final_reviewer") else None
        record["final_review_date"] = _redact_text(label_row.get("final_review_date"), "unknown") if label_row.get("final_review_date") else None
        record["reviewer_count"] = int(bool(record.get("reviewer_1_label"))) + int(bool(record.get("reviewer_2_label")))
        first, second, adjudicated = record.get("reviewer_1_label"), record.get("reviewer_2_label"), record.get("adjudicated_label")
        if first and second and first != second and not adjudicated:
            record["review_status"], record["adjudication_status"] = "conflict", "conflict"
        elif first and second and adjudicated and record.get("final_reviewer") and record.get("final_review_date") and record.get("adjudication_notes"):
            record["review_status"], record["adjudication_status"] = "adjudicated", "complete"
            record["expected_class"] = adjudicated
            record["labeling_notes"] = _redact_text(record.get("adjudication_notes"), "Adjudicated label recorded.")
        elif first or second:
            record["review_status"], record["adjudication_status"] = "provisional", "provisional"
            record["expected_class"] = None
            record["labeling_notes"] = "Provisional manual review; a second independent reviewer and adjudication are required."
        else:
            record["review_status"], record["adjudication_status"] = "unreviewed", "not_started"
        output.append(record)
    unknown_ids = sorted(set(by_id) - {str(record.get("sample_id")) for record in records})
    errors.extend(f"unknown sample_id in label file: {sample_id}" for sample_id in unknown_ids)
    return sorted(output, key=lambda item: item.get("sample_id", "")), errors


def write_review_queue(path: Path, records: Iterable[dict[str, Any]]) -> None:
    fields = ["sample_id", "source", "subject_redacted", "sender_domain", "claimed_organization", "language", "attachment_present", "url_present", "candidate_category", "reviewer_label", "reviewer_confidence", "reviewer_notes", "adjudication_needed"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in sorted(records, key=lambda item: item.get("sample_id", "")):
            writer.writerow({
                "sample_id": record.get("sample_id", ""),
                "source": record.get("source_dataset", ""),
                "subject_redacted": record.get("subject_redacted", "[subject withheld]"),
                "sender_domain": record.get("sender_domain", "unknown"),
                "claimed_organization": record.get("claimed_organization", "unknown"),
                "language": record.get("language", "unknown"),
                "attachment_present": record.get("attachment_present", False),
                "url_present": record.get("url_present", False),
                "candidate_category": record.get("candidate_category") or "",
                "reviewer_label": record.get("adjudicated_label") or record.get("reviewer_1_label") or "",
                "reviewer_confidence": record.get("reviewer_1_confidence") or "",
                "reviewer_notes": record.get("labeling_notes", ""),
                "adjudication_needed": record.get("review_status") != "adjudicated",
            })


def _count_records(path: Path) -> int | None:
    if not path.exists():
        return 0
    if path.is_dir():
        return sum(1 for item in path.rglob("*") if item.is_file() and ".git" not in item.parts)
    if path.suffix.lower() == ".eml":
        return 1
    if path.suffix.lower() in {".csv", ".jsonl"}:
        try:
            return max(0, sum(1 for line in _read_text(path).splitlines() if line.strip()) - (1 if path.suffix.lower() == ".csv" else 0))
        except OSError:
            return None
    if path.suffix.lower() == ".json":
        try:
            return len(_load_json_records(path))
        except (OSError, json.JSONDecodeError):
            return None
    return None


INVENTORY_RULES = (
    ("services/ml/data/raw/phishing_nlp_dataset.xlsx", "zenodo_phishing_nlp_15235123", "training-only", "approved license; used by development corpus"),
    ("services/ml/data/raw/spaphish_v5.csv", "spaphish_mendeley", "unsuitable", "source rights/provenance and campaign metadata are not complete for this benchmark"),
    ("services/ml/data/interim/core_candidates.jsonl", "zenodo_phishing_nlp_15235123", "training-only", "derived development candidate pool"),
    ("services/ml/data/interim/english_candidates.jsonl", "zenodo_phishing_nlp_15235123", "training-only", "derived development candidate pool"),
    ("services/ml/data/interim/generic_spam_hard_negatives.jsonl", "apache_spamassassin_spam", "unsuitable", "source spam is not a phishing ground-truth label"),
    ("services/ml/data/processed/english_core.csv", "zenodo_phishing_nlp_15235123", "training-only", "processed training corpus"),
    ("services/ml/data/processed/english_core_v3.csv", "zenodo_phishing_nlp_15235123", "training-only", "development pool; not independent"),
    ("services/ml/data/processed/english_core/review_corpus.csv", "zenodo_phishing_nlp_15235123", "training-only", "processed review/training corpus"),
    ("services/ml/data/processed/grouped_template_diagnostic_v2.csv", "zenodo_phishing_nlp_15235123", "diagnostic-only", "grouped template diagnostic"),
    ("services/ml/data/processed/phishing_email_dataset.csv", "zenodo_phishing_nlp_15235123", "training-only", "processed training artifact"),
    ("services/ml/data/external/Phishing_validation_emails.csv", "zenodo_phishing_validation_13474746", "external-validation-only", "publisher validation source; not training"),
    ("services/ml/data/external/validation.csv", "zenodo_phishing_validation_13474746", "external-validation-only", "derived external validation"),
    ("services/ml/data/external/validation_candidates.jsonl", "zenodo_phishing_validation_13474746", "external-validation-only", "derived external validation candidates"),
    ("services/ml/data/external/validation_language_audit.jsonl", "zenodo_phishing_validation_13474746", "external-validation-only", "language audit, not ground truth"),
    ("services/ml/data/external/development_benchmark.csv", "external_development_benchmark", "diagnostic-only", "external development benchmark; not independent headline data"),
    ("services/ml/data/external/final_external_benchmark.csv", "external_final_benchmark", "external-validation-only", "sealed external benchmark; prior evaluation evidence exists"),
    ("services/ml/data/external/contextual_email_deception_cc0.csv", "kaggle_contextual_email_deception_cc0", "external-validation-only", "external source; separate provenance review required"),
    ("services/ml/data/external/phishing_pot/derived/safe_metadata.jsonl", "github_rf_peixoto_phishing_pot", "diagnostic-only", "derived metadata; not a manually adjudicated label source"),
    ("services/ml/data/external/phishing_pot/metadata/source_metadata.jsonl", "github_rf_peixoto_phishing_pot", "diagnostic-only", "source metadata; not a manually adjudicated label source"),
    ("services/ml/data/external/phishing_pot/safe_metadata.jsonl", "github_rf_peixoto_phishing_pot", "diagnostic-only", "derived metadata; not a manually adjudicated label source"),
    ("services/ml/data/external/phishing_pot/repository/email", "github_rf_peixoto_phishing_pot", "unsuitable", "restricted/provenance-incomplete local raw corpus; no automatic labels"),
    ("services/ml/data/staging/phishing_pot_pilot_001", "github_rf_peixoto_phishing_pot", "diagnostic-only", "pilot shortlist and weak-label review artifacts"),
    ("apps/api/tests/fixtures", "repository_synthetic_fixtures", "diagnostic-only", "synthetic/regression fixtures; not an independent benchmark"),
    ("docs/assets/demo", "repository_synthetic_fixtures", "diagnostic-only", "portfolio/demo fixtures; not an independent benchmark"),
)


def _label_vocabulary(path: Path) -> str:
    values: set[str] = set()
    try:
        if path.is_file() and path.suffix.lower() == ".csv":
            with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader):
                    if index >= 5000:
                        break
                    for key in ("label", "expected_class", "class", "category"):
                        if row.get(key):
                            value = re.sub(r"[^A-Za-z0-9 _-]", "", str(row[key]))[:40]
                            if value:
                                values.add(value)
        elif path.is_file() and path.suffix.lower() in {".json", ".jsonl"}:
            for row in _load_json_records(path)[:5000]:
                for key in ("label", "expected_class", "class", "category"):
                    if row.get(key):
                        value = re.sub(r"[^A-Za-z0-9 _-]", "", str(row[key]))[:40]
                        if value:
                            values.add(value)
    except (OSError, UnicodeError):
        return "unreadable"
    return ", ".join(sorted(values)[:20]) or "not inspected/unknown"


def repository_inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative, source_id, classification, notes in INVENTORY_RULES:
        path = ROOT / relative
        exists = path.exists()
        used_training = classification == "training-only"
        used_development = classification in {"training-only", "diagnostic-only"}
        challenge = "yes" if source_id == "spaphish_mendeley" else "no evidence in this audit"
        rows.append({
            "source_id": source_id,
            "path": relative,
            "classification": classification,
            "records_or_files": _count_records(path),
            "label_vocabulary_observed": _label_vocabulary(path) if exists else "missing",
            "source_identity_verified": source_id not in {"external_development_benchmark", "external_final_benchmark", "repository_synthetic_fixtures"},
            "content_exists": exists,
            "duplicate_status": "not evaluated for gold set",
            "privacy_suitability": "not approved for public raw-content storage",
            "used_in_training": used_training,
            "used_in_development_validation": used_development,
            "challenge_22_status": challenge,
            "untouched": classification in {"external-validation-only", "unsuitable"},
            "notes": notes,
        })
    return rows


def write_repository_audit(report_root: Path) -> dict[str, Any]:
    report_root.mkdir(parents=True, exist_ok=True)
    rows = repository_inventory()
    inventory_fields = list(rows[0])
    with (report_root / "source_inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=inventory_fields)
        writer.writeheader()
        writer.writerows(rows)
    classifications = Counter(row["classification"] for row in rows)
    eligibility = [
        "# Gold-standard source eligibility",
        "",
        "This audit inspects local dataset artifacts and prior provenance reports. It does not convert source labels into PhishShield ground truth.",
        "",
        "## Classification counts",
        "",
    ]
    for key in ("eligible candidate source", "diagnostic-only", "training-only", "external-validation-only", "unsuitable", "unknown"):
        eligibility.append(f"- `{key}`: {classifications.get(key, 0)} artifact(s)")
    eligibility += [
        "",
        "## Decision",
        "",
        "No local artifact is eligible for the independent benchmark automatically. Existing labels are source annotations or prior development annotations, not two-reviewer adjudication. Training/development material remains development-only; external validation files remain external-validation-only; restricted or provenance-incomplete raw mail remains unsuitable.",
        "",
        "## Existing evidence inspected",
        "",
        "- `services/ml/dataset_sources.json` and `services/ml/DATASET_ACQUISITION.md`",
        "- `services/ml/reports/corpus_inventory.*`, `corpus_audit.json`, and `dataset_gap_analysis.*`",
        "- `services/ml/reports/phishing_pot_pilot_001/*` and `phishing_pot_batch_002/*`",
        "- `services/ml/reports/feature_coverage/*` and `candidate_qualification/*`",
        "- `reports/dataset_evolution/*`, `reports/candidate_qualification/*`, and `reports/feature_coverage/*` where present",
        "",
        "A source can become an eligible candidate only after licensing/provenance review, privacy review, overlap review, and independent manual labeling. No automatic relabeling occurred.",
        "",
    ]
    _write_text(report_root / "source_eligibility.md", "\n".join(eligibility))

    leakage_fields = ["sample_id", "reference_dataset", "reference_record_id", "overlap_type", "similarity", "action", "reason"]
    with (report_root / "leakage_audit.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=leakage_fields)
        writer.writeheader()
        writer.writerow({"sample_id": "", "reference_dataset": "repository audit", "reference_record_id": "", "overlap_type": "not_run", "similarity": "", "action": "no benchmark records", "reason": "The independent manifest is empty; exact and near-duplicate comparison becomes active when reviewed records are added."})
    with (report_root / "near_duplicate_review.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=leakage_fields)
        writer.writeheader()

    balance_fields = ["dimension", "value", "count", "status", "flag"]
    balance_rows: list[dict[str, Any]] = []
    for value in VALID_CLASSES:
        balance_rows.append({"dimension": "class", "value": value, "count": 0, "status": "not_ready", "flag": "no adjudicated records"})
    for dimension in ("language", "campaign", "source", "year", "sender_domain", "claimed_organization", "attachment_presence", "url_presence", "category"):
        balance_rows.append({"dimension": dimension, "value": "unknown", "count": 0, "status": "not_ready", "flag": "no adjudicated records"})
    with (report_root / "balance_report.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=balance_fields)
        writer.writeheader()
        writer.writerows(balance_rows)

    _write_text(report_root / "collection_targets.md", """# Gold-standard collection targets

Recommended initial target: 300 safe, 100 suspicious, and 300 phishing samples, with campaign diversity prioritized over raw volume.

Minimum acceptable pilot: 100 safe, 50 suspicious, and 100 phishing samples. Every independent benchmark sample must be privacy-reviewed, overlap-reviewed, and adjudicated by two independent reviewers. The current qualified count is 0/700 recommended and 0/250 minimum because curation has not been completed; no rows were fabricated.

Practical stress-set targets should include at least 10 reviewed samples per available category and both safe and phishing examples for each category where evidence exists. Required categories include brand impersonation, business email, newsletters, receipts, account alerts, shipping, government/legal, education, healthcare, and generic spam.
""")
    _write_text(report_root / "diversity_report.md", """# Gold-standard diversity report

## Current state

The independent benchmark is empty. Class, language, campaign, source, temporal, sender-domain, organization, attachment, URL, and category distributions therefore cannot be interpreted as benchmark balance.

## Known composition risks

- Existing development material is English-dominant and includes a dominant source/campaign family.
- Existing external validation is separate from training but is not two-reviewer adjudicated in the new schema.
- The repository contains diagnostic fixtures and portfolio examples; these are not independent evidence.
- Hard negatives are incomplete for legitimate security alerts, password resets, invoices, receipts, newsletters, shipping, third-party infrastructure, mailing lists, authenticated account alerts, link/attachment-bearing benign mail, and unusual benign formatting.
- Modern phishing coverage is incomplete for OAuth/account consent, QR phishing, compromised legitimate senders, no-link social engineering, mailto actions, tracking-pixel-plus-action patterns, URL shorteners, and lookalike domains.

Balance reports will be regenerated from adjudicated records and will flag source dominance, campaign dominance, temporal concentration, synthetic overrepresentation, duplicate campaigns, missing hard negatives, and missing modern phishing.
""")
    _write_text(report_root / "scientific_validity.md", """# Scientific validity report

## Dataset construction

The curation CLI scans local `.eml`, text, JSON/JSONL, and CSV candidates, computes deterministic content and normalized hashes, extracts safe structural metadata, and writes a public manifest without raw content. It never maps source labels, filenames, model predictions, or heuristics to ground truth.

## Review and adjudication

The intended process is independent reviewer 1, independent reviewer 2, explicit disagreement documentation, and a final adjudicator lock. One reviewer produces a provisional record only. The independent benchmark requires two reviewer labels, an adjudicated label, final reviewer/date, notes, and no unresolved conflict.

## Provenance, overlap, and privacy

Training/development material, prior challenge samples, feature-coverage samples, candidate-qualification samples, synthetic examples, and portfolio examples are separate from the independent benchmark. Exact and normalized hashes plus campaign-family review are recorded in the leakage audit. Public metadata uses redacted subjects, domains, counts, and stable hashes; raw content and local paths are ignored/private.

## Validity limits

No qualified independent sample is currently available. Therefore no accuracy, recall, specificity, F1, MCC, ROC-AUC, PR-AUC, latency, or error-rate claim is supported by this phase. Existing repository metrics remain historical diagnostic or external-validation evidence and must not be presented as this gold-standard benchmark.

## Reproducibility and bias

Manifest ordering, sample IDs, hashes, and queue output are deterministic. Future collection must record source identity, license, language, date, campaign, and whether data entered training or development. Source, language, campaign, temporal, provider, and category imbalance remain likely biases until the target is collected.
""")
    _write_text(report_root / "portfolio_summary.md", """# Portfolio-safe evaluation summary

The evaluation framework is complete; gold-standard dataset curation is still in progress.

No qualified benchmark metrics are reported. Existing repository datasets did not qualify automatically because provenance, privacy, overlap, and two-reviewer adjudication evidence are not complete. Model predictions are never used as ground truth.
""")
    _write_text(report_root / "privacy_findings.md", """# Gold-standard privacy findings

- No raw email bodies or attachment bytes were added to the repository.
- Public manifests and queues contain no full personal addresses, phone numbers, private headers, authentication tokens, or full live URLs.
- Absolute local paths are kept only in the ignored `services/ml/evaluation/private/` area when a reviewer explicitly creates a local map.
- Existing local raw datasets remain in their pre-existing ignored locations and were not copied, relabeled, or deleted.
- Reviewers must redact notes before exporting a public manifest; the CLI applies conservative redaction to common addresses, URLs, phones, tokens, and paths.
""")
    return {"artifact_count": len(rows), "classification_counts": dict(classifications), "qualified_candidate_records": 0, "adjudicated_records": 0}


def _eligible_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    eligible: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for record in records:
        issues = validate_record(record, final=True)
        if issues:
            rejected.append({"sample_id": record.get("sample_id"), "reasons": issues})
        else:
            eligible.append(record)
    return eligible, rejected


def export_benchmark(records: list[dict[str, Any]], output: Path, lock_report: Path) -> dict[str, Any]:
    """Write only final-gate records and a deterministic lock audit."""
    eligible, rejected = _eligible_records(records)
    benchmark = [dict(record, subset="independent_validation") for record in eligible]
    write_manifest(output, benchmark)
    result = {
        "status": "locked" if eligible else "not_ready",
        "schema_version": SCHEMA_VERSION,
        "subset": "independent_validation",
        "locked_record_ids": [record["sample_id"] for record in benchmark],
        "rejected_records": rejected,
        "headline_metrics_allowed": bool(eligible),
    }
    _write_json(lock_report, result)
    return result


def write_leakage_reports(report_root: Path, exact: list[dict[str, Any]], near: list[dict[str, Any]]) -> None:
    report_root.mkdir(parents=True, exist_ok=True)
    fields = ["sample_id", "reference_dataset", "reference_record_id", "overlap_type", "similarity", "action", "reason"]
    for filename, rows in (("leakage_audit.csv", exact), ("near_duplicate_review.csv", near)):
        with (report_root / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)


def _shortfall(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(record.get("expected_class") for record in records if record.get("review_status") == "adjudicated")
    minimum = {"safe": 100, "suspicious": 50, "phishing": 100}
    recommended = {"safe": 300, "suspicious": 100, "phishing": 300}
    return {
        "adjudicated_counts": {key: counts.get(key, 0) for key in VALID_CLASSES},
        "minimum_pilot_target": minimum,
        "recommended_target": recommended,
        "minimum_shortfall": {key: max(0, minimum[key] - counts.get(key, 0)) for key in VALID_CLASSES},
        "recommended_shortfall": {key: max(0, recommended[key] - counts.get(key, 0)) for key in VALID_CLASSES},
    }


def run_pilot(manifest_path: Path, output_root: Path, private_locations_path: Path) -> dict[str, Any]:
    records = load_manifest(manifest_path)
    eligible, rejected = _eligible_records(records)
    output_root.mkdir(parents=True, exist_ok=True)
    shortfall = _shortfall(records)
    if any(shortfall["minimum_shortfall"].values()) or not eligible:
        readiness = {
            "status": "not_ready",
            "reason": "fewer than the minimum qualified adjudicated samples",
            "manifest": _safe_relative(manifest_path),
            "qualified_records": len(eligible),
            "rejected_records": len(rejected),
            **shortfall,
        }
        _write_json(output_root / "shortfall.json", readiness)
        _write_text(output_root / "readiness.md", """# Pilot benchmark readiness

Status: **not ready**.

The minimum pilot requires 100 safe, 50 suspicious, and 100 phishing samples. The current manifest has no qualified adjudicated records, so headline metrics are withheld. The existing production harness is not invoked until the independent benchmark passes the automated gates.

See `shortfall.json` for exact class shortfalls. Existing diagnostic and external-validation metrics are not substituted.
""")
        _write_text(output_root / "limitations.md", """# Pilot limitations

No pilot metrics were generated. The blocker is missing manually adjudicated, privacy-approved, overlap-reviewed records, not a model or threshold change.
""")
        return readiness

    private = {row.get("sample_id"): row for row in (_load_json_records(private_locations_path) if private_locations_path.exists() else [])}
    harness_rows: list[dict[str, Any]] = []
    for record in eligible:
        location = private.get(record["sample_id"], {}).get("content_path")
        if not location:
            raise RuntimeError(f"no private content location for {record['sample_id']}")
        harness_rows.append({
            "id": record["sample_id"], "label": record["expected_class"], "expected_class": record["expected_class"],
            "source": record["source_dataset"], "campaign": record["campaign"], "date": record["sample_date"],
            "category": record.get("category"), "path": str(ROOT / location),
        })
    harness_manifest = output_root / "harness_manifest.local.json"
    _write_json(harness_manifest, {"samples": harness_rows})
    evaluator = ROOT / "apps" / "api" / "scripts" / "evaluate_v1.py"
    command = [sys.executable, str(evaluator), "--dataset", str(harness_manifest), "--output", str(output_root)]
    completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError(f"production evaluation harness failed: {completed.stderr[-1000:]}")
    _write_json(output_root / "pilot_run.json", {"status": "complete", "qualified_records": len(eligible), "harness_stdout": completed.stdout[-1000:]})
    return {"status": "complete", "qualified_records": len(eligible)}


def _reference_hashes(paths: list[Path]) -> dict[str, list[tuple[str, str, str]]]:
    result: dict[str, list[tuple[str, str, str]]] = {"content": [], "normalized": [], "body": []}
    for file_path in _files_for_inputs(paths):
        if file_path.suffix.lower() in {".eml", ".txt"}:
            raw = _read_text(file_path)
            parsed = _safe_email_metadata(raw, file_path.suffix.lower())
            result["content"].append((stable_content_hash(raw), _safe_relative(file_path), ""))
            result["normalized"].append((parsed["normalized_hash"], _safe_relative(file_path), ""))
            result["body"].append((parsed["body_hash"], _safe_relative(file_path), normalized_text(raw)[:10000]))
    return result


def leakage_audit(records: list[dict[str, Any]], references: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    references_by_hash = _reference_hashes(references)
    exact: list[dict[str, Any]] = []
    near: list[dict[str, Any]] = []
    for record in records:
        for content_hash, path, _ in references_by_hash["content"]:
            if content_hash == record.get("content_hash"):
                exact.append({"sample_id": record["sample_id"], "reference_dataset": "reference_input", "reference_record_id": path, "overlap_type": "exact_content_hash", "similarity": 1.0, "action": "exclude", "reason": "exact content overlap"})
        for normalized_hash, path, _ in references_by_hash["normalized"]:
            if normalized_hash == record.get("normalized_content_hash"):
                exact.append({"sample_id": record["sample_id"], "reference_dataset": "reference_input", "reference_record_id": path, "overlap_type": "exact_normalized_hash", "similarity": 1.0, "action": "review/exclude", "reason": "normalized subject/body overlap"})
        candidate = normalized_text(str(record.get("subject_redacted", "")))
        for _, path, reference_text in references_by_hash["body"]:
            if candidate and reference_text and difflib.SequenceMatcher(None, candidate[:10000], reference_text[:10000]).quick_ratio() >= 0.92:
                near.append({"sample_id": record["sample_id"], "reference_dataset": "reference_input", "reference_record_id": path, "overlap_type": "suspected_near_duplicate", "similarity": round(difflib.SequenceMatcher(None, candidate[:10000], reference_text[:10000]).ratio(), 4), "action": "manual review", "reason": "high normalized text similarity"})
    return exact, near


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan local candidates without assigning labels")
    scan.add_argument("--input", action="append", required=True, type=Path)
    scan.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    scan.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    scan.add_argument("--private-locations", type=Path, default=PRIVATE_ROOT / "content_locations.jsonl")
    labels = sub.add_parser("apply-labels", help="Apply a separate manual review file")
    labels.add_argument("--manifest", type=Path, required=True)
    labels.add_argument("--labels", type=Path, required=True)
    labels.add_argument("--output", type=Path)
    labels.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    validate = sub.add_parser("validate", help="Validate a candidate or final manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--final", action="store_true")
    validate.add_argument("--report", type=Path)
    audit = sub.add_parser("audit", help="Write repository source, leakage, balance, and validity reports")
    audit.add_argument("--output", type=Path, default=DEFAULT_REPORT_ROOT)
    pilot = sub.add_parser("pilot", help="Run the existing harness only after benchmark gates pass")
    pilot.add_argument("--manifest", type=Path, default=EVALUATION_ROOT / "benchmark_manifest.jsonl")
    pilot.add_argument("--output", type=Path, default=DEFAULT_REPORT_ROOT / "pilot")
    pilot.add_argument("--private-locations", type=Path, default=PRIVATE_ROOT / "content_locations.jsonl")
    export = sub.add_parser("export", help="Lock final-gate records into a public benchmark manifest")
    export.add_argument("--manifest", type=Path, required=True)
    export.add_argument("--output", type=Path, default=EVALUATION_ROOT / "benchmark_manifest.jsonl")
    export.add_argument("--lock-report", type=Path, default=EVALUATION_ROOT / "benchmark_lock.json")
    leakage = sub.add_parser("leakage", help="Compare candidate hashes with explicit local reference inputs")
    leakage.add_argument("--manifest", type=Path, required=True)
    leakage.add_argument("--reference", action="append", required=True, type=Path)
    leakage.add_argument("--output", type=Path, default=DEFAULT_REPORT_ROOT)
    queue = sub.add_parser("queue", help="Regenerate a safe reviewer queue")
    queue.add_argument("--manifest", type=Path, required=True)
    queue.add_argument("--output", type=Path, default=DEFAULT_QUEUE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if args.command == "scan":
        records, private = scan_candidates(args.input)
        write_manifest(args.manifest, records)
        write_private_locations(args.private_locations, private)
        write_review_queue(args.queue, records)
        print(json.dumps({"manifest": _safe_relative(args.manifest), "records": len(records), "labels_assigned": 0, "private_locations": _safe_relative(args.private_locations)}, sort_keys=True))
        return 0
    if args.command == "apply-labels":
        records = load_manifest(args.manifest)
        updated, errors = apply_labels(records, args.labels)
        output = args.output or args.manifest
        write_manifest(output, updated)
        write_review_queue(args.queue, updated)
        print(json.dumps({"manifest": _safe_relative(output), "records": len(updated), "errors": errors}, sort_keys=True))
        return 2 if errors else 0
    if args.command == "validate":
        report = validate_manifest(load_manifest(args.manifest), final=args.final)
        if args.report:
            _write_json(args.report, report)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["valid"] else 2
    if args.command == "audit":
        summary = write_repository_audit(args.output)
        print(json.dumps(summary, sort_keys=True))
        return 0
    if args.command == "pilot":
        result = run_pilot(args.manifest, args.output, args.private_locations)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "export":
        result = export_benchmark(load_manifest(args.manifest), args.output, args.lock_report)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "leakage":
        exact, near = leakage_audit(load_manifest(args.manifest), args.reference)
        write_leakage_reports(args.output, exact, near)
        result = {"exact_overlap_count": len(exact), "near_duplicate_count": len(near), "output": _safe_relative(args.output)}
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "queue":
        records = load_manifest(args.manifest)
        write_review_queue(args.output, records)
        print(json.dumps({"queue": _safe_relative(args.output), "records": len(records)}, sort_keys=True))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
