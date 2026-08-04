"""Deterministic, private-only evaluation of approved gold records.

The privacy-safe gold export contains review metadata and digests, not message
text.  This module joins those records to the sanitized subject/body previews
already stored in the ignored review SQLite database.  The previews are used
only in memory as the existing ``text`` input expected by the ML evaluator;
they are never written to evaluation artifacts.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any, Mapping, Sequence

from .evaluation import evaluate_predictions
from .preprocessing import combine_email_fields


EVALUATION_SCRIPT_VERSION = "gold-dataset-evaluation-v1.0.0"
GOLD_EXPORT_VERSION = "gold-dataset-v1"
GOLD_LABEL_MAPPING = {"safe": 0, "phishing": 1}
GOLD_EXPORT_FIELDS = frozenset(
    {
        "campaign_identifier",
        "export_version",
        "human_label_authority",
        "label_quality",
        "language",
        "phishing_label",
        "review_id",
        "review_notes",
        "review_version",
        "reviewer_confidence",
        "sample_hash",
        "source_dataset",
        "source_sample_id_digest",
    }
)
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|javascript|data|file|blob|chrome):[^\s<>]+")
_PATH_RE = re.compile(r"(?i)(?:[A-Za-z]:\\|/Users/|/home/|/tmp/|/var/|file://)[^\s]+")
_HEADER_RE = re.compile(
    r"(?im)^(?:from|to|cc|bcc|subject|received|message-id|authentication-results|return-path):"
)
_HTML_RE = re.compile(r"(?is)<\s*/?\s*[a-z][^>]*>")
_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|admin[_ -]?token|access[_ -]?token|bearer)\s*[:=]\s*[^\s]+"
)


class GoldEvaluationError(ValueError):
    """Base error for fail-closed gold evaluation preparation."""


class GoldSchemaError(GoldEvaluationError):
    """The exported JSONL does not match the audited schema."""


class GoldApprovalError(GoldEvaluationError):
    """A record is not demonstrably approved in the private review store."""


class DuplicateGoldHashError(GoldEvaluationError):
    """A stable sample or normalized-content hash is duplicated."""


class GoldPrivacyError(GoldEvaluationError):
    """Private or unsafe content was found in the evaluation input."""


@dataclass(frozen=True)
class GoldExportRecord:
    line_number: int
    values: dict[str, Any]


@dataclass(frozen=True)
class ApprovedContentRecord:
    review_id: str
    state: str
    sample_hash: str
    normalized_content_hash: str
    source_dataset: str
    source_sample_id: str
    campaign_identifier: str
    phishing_label: str
    subject: str
    body_excerpt: str
    # These fields are already privacy-sanitized metadata in the private
    # review store.  They are optional to preserve the adapter's small test
    # fixture contract and are never written to evaluation reports.
    sender_domain: str = ""
    reply_to_domain: str = ""
    authentication_summary: tuple[str, ...] = ()
    url_domains: tuple[str, ...] = ()
    url_structural_flags: tuple[str, ...] = ()
    attachment_metadata: str = ""


@dataclass(frozen=True)
class GoldEvaluationInput:
    """Existing ML evaluation shape plus privacy-safe provenance metadata."""

    sample_id: str
    source_dataset: str
    label_name: str
    label: int
    text: str
    sample_hash: str
    normalized_content_hash: str


def _sha256_text(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _reject(line_number: int, message: str) -> GoldSchemaError:
    return GoldSchemaError(f"Malformed gold record at line {line_number}: {message}.")


def _validate_digest(value: Any, field: str, line_number: int) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise _reject(line_number, f"invalid {field}")
    return value


def _privacy_violations(text: str) -> list[str]:
    violations: list[str] = []
    if _EMAIL_RE.search(text):
        violations.append("email_address")
    if _URL_RE.search(text):
        violations.append("full_url")
    if _PATH_RE.search(text):
        violations.append("absolute_path")
    if _HEADER_RE.search(text):
        violations.append("raw_header")
    if _HTML_RE.search(text):
        violations.append("raw_html")
    if _SECRET_RE.search(text):
        violations.append("secret_like_token")
    return violations


def load_export_records(path: str | Path) -> list[GoldExportRecord]:
    """Load and strictly validate the audited privacy-safe JSONL schema."""

    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GoldSchemaError("Gold dataset export could not be read.") from error

    records: list[GoldExportRecord] = []
    seen_sample_hashes: dict[str, int] = {}
    seen_sample_ids: dict[str, int] = {}
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise _reject(line_number, "invalid JSON") from error
        if not isinstance(payload, dict):
            raise _reject(line_number, "record must be an object")
        keys = frozenset(payload)
        if keys != GOLD_EXPORT_FIELDS:
            missing = GOLD_EXPORT_FIELDS - keys
            extra = keys - GOLD_EXPORT_FIELDS
            detail = "schema fields do not match"
            if missing:
                detail += " (missing fields)"
            if extra:
                detail += " (unsupported fields)"
            raise _reject(line_number, detail)
        if payload["export_version"] != GOLD_EXPORT_VERSION:
            raise _reject(line_number, "unsupported export version")
        if payload["phishing_label"] not in GOLD_LABEL_MAPPING:
            raise _reject(line_number, "unsupported phishing label")
        if payload["human_label_authority"] is not True:
            raise _reject(line_number, "human label authority is not true")
        if payload["label_quality"] != "high":
            raise _reject(line_number, "label quality is not high")
        if payload["review_notes"] != "[redacted for privacy-safe export]":
            raise _reject(line_number, "review notes are not redacted")
        if not all(isinstance(payload[field], str) and payload[field].strip() for field in (
            "review_id", "language", "review_version"
        )):
            raise _reject(line_number, "required metadata is empty")
        confidence = payload["reviewer_confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
            raise _reject(line_number, "invalid reviewer confidence")
        sample_hash = _validate_digest(payload["sample_hash"], "sample_hash", line_number)
        _validate_digest(payload["source_dataset"], "source_dataset", line_number)
        sample_id = _validate_digest(payload["source_sample_id_digest"], "source_sample_id_digest", line_number)
        _validate_digest(payload["campaign_identifier"], "campaign_identifier", line_number)
        metadata_text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        if _privacy_violations(metadata_text):
            raise _reject(line_number, "privacy-sensitive metadata")
        if sample_hash in seen_sample_hashes:
            raise DuplicateGoldHashError("Duplicate sample hash in the gold export.")
        if sample_id in seen_sample_ids:
            raise DuplicateGoldHashError("Duplicate privacy-safe sample ID in the gold export.")
        seen_sample_hashes[sample_hash] = line_number
        seen_sample_ids[sample_id] = line_number
        records.append(GoldExportRecord(line_number=line_number, values=dict(payload)))
    if not records:
        raise GoldSchemaError("The gold dataset export contains no records.")
    return records


def load_approved_content(path: str | Path) -> dict[str, ApprovedContentRecord]:
    """Read sanitized previews from SQLite without allowing writes."""

    source = Path(path)
    if not source.exists():
        raise GoldApprovalError("The private review store is missing.")
    try:
        connection = sqlite3.connect(source, uri=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            """
            SELECT g.review_id, g.state, g.sample_hash, g.normalized_content_hash,
                   g.source_dataset, g.source_sample_id, g.campaign_identifier,
                   g.phishing_label, i.subject_preview, i.body_excerpt,
                   i.sender_domain, i.reply_to_domain,
                   i.authentication_summary_json, i.url_domains_json,
                   i.url_structural_flags_json, i.attachment_metadata
            FROM gold_reviews AS g
            JOIN dataset_review_items AS i ON i.current_review_id = g.review_id
            WHERE g.state = 'approved'
            ORDER BY g.review_id
            """
        ).fetchall()
    except (OSError, sqlite3.Error) as error:
        raise GoldApprovalError("The private approved-record store could not be read.") from error
    finally:
        try:
            connection.close()
        except (UnboundLocalError, AttributeError):
            pass

    approved: dict[str, ApprovedContentRecord] = {}
    for row in rows:
        review_id = str(row["review_id"])
        if review_id in approved:
            raise GoldApprovalError("The private review store contains a duplicate review ID.")
        try:
            authentication_summary = json.loads(row["authentication_summary_json"] or "[]")
            url_domains = json.loads(row["url_domains_json"] or "[]")
            url_structural_flags = json.loads(row["url_structural_flags_json"] or "[]")
        except (TypeError, json.JSONDecodeError) as error:
            raise GoldApprovalError("The private review store contains malformed sanitized metadata.") from error
        if not all(isinstance(value, list) and all(isinstance(item, str) for item in value) for value in (
            authentication_summary, url_domains, url_structural_flags
        )):
            raise GoldApprovalError("The private review store contains malformed sanitized metadata.")
        approved[review_id] = ApprovedContentRecord(
            review_id=review_id,
            state=str(row["state"]),
            sample_hash=str(row["sample_hash"]),
            normalized_content_hash=str(row["normalized_content_hash"]),
            source_dataset=str(row["source_dataset"]),
            source_sample_id=str(row["source_sample_id"]),
            campaign_identifier=str(row["campaign_identifier"]),
            phishing_label=str(row["phishing_label"]),
            subject=str(row["subject_preview"] or ""),
            body_excerpt=str(row["body_excerpt"] or ""),
            sender_domain=str(row["sender_domain"] or ""),
            reply_to_domain=str(row["reply_to_domain"] or ""),
            authentication_summary=tuple(authentication_summary),
            url_domains=tuple(url_domains),
            url_structural_flags=tuple(url_structural_flags),
            attachment_metadata=str(row["attachment_metadata"] or ""),
        )
    return approved


def adapt_approved_records(
    export_records: Sequence[GoldExportRecord],
    approved_content: Mapping[str, ApprovedContentRecord],
) -> list[GoldEvaluationInput]:
    """Join approved metadata to sanitized content and produce ``text,label`` inputs."""

    adapted: list[GoldEvaluationInput] = []
    seen_normalized_hashes: set[str] = set()
    seen_sample_hashes: set[str] = set()
    for record in export_records:
        values = record.values
        review_id = str(values["review_id"])
        content = approved_content.get(review_id)
        if content is None or content.state != "approved":
            raise GoldApprovalError("Every exported record must join to an approved review.")
        if values["phishing_label"] != content.phishing_label:
            raise GoldApprovalError("Export label does not match the approved review label.")
        if values["sample_hash"] != _sha256_text(content.sample_hash):
            raise GoldApprovalError("Export sample hash does not match the approved review.")
        if values["source_dataset"] != _sha256_text(content.source_dataset):
            raise GoldApprovalError("Export source digest does not match the approved review.")
        if values["source_sample_id_digest"] != _sha256_text(content.source_sample_id):
            raise GoldApprovalError("Export sample ID digest does not match the approved review.")
        if values["campaign_identifier"] != _sha256_text(content.campaign_identifier):
            raise GoldApprovalError("Export campaign digest does not match the approved review.")
        if values["sample_hash"] in seen_sample_hashes or content.normalized_content_hash in seen_normalized_hashes:
            raise DuplicateGoldHashError("Duplicate sample or normalized-content hash in approved gold records.")
        seen_sample_hashes.add(values["sample_hash"])
        seen_normalized_hashes.add(content.normalized_content_hash)
        if not content.subject.strip() and not content.body_excerpt.strip():
            raise GoldSchemaError("An approved record has no usable sanitized content.")
        content_text = f"{content.subject}\n{content.body_excerpt}"
        violations = _privacy_violations(content_text)
        if violations:
            raise GoldPrivacyError("Approved content failed the privacy safety gate.")
        text = combine_email_fields(content.subject, content.body_excerpt)
        if not text:
            raise GoldSchemaError("An approved record has no usable evaluation text.")
        label_name = str(values["phishing_label"])
        adapted.append(
            GoldEvaluationInput(
                sample_id=str(values["source_sample_id_digest"]),
                source_dataset=str(values["source_dataset"]),
                label_name=label_name,
                label=GOLD_LABEL_MAPPING[label_name],
                text=text,
                sample_hash=str(values["sample_hash"]),
                normalized_content_hash=content.normalized_content_hash,
            )
        )
    return sorted(adapted, key=lambda item: (item.sample_id, item.sample_hash))


def adapt_approved_gold_dataset(dataset_path: str | Path, review_db_path: str | Path) -> list[GoldEvaluationInput]:
    """Load, approve-filter, validate, and deterministically adapt the gold set."""

    return adapt_approved_records(load_export_records(dataset_path), load_approved_content(review_db_path))


def _probability_summary(probabilities: Sequence[float]) -> dict[str, float | int | None]:
    if not probabilities:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None, "p90": None}
    values = sorted(float(value) for value in probabilities)
    p90_index = min(len(values) - 1, max(0, math.ceil(len(values) * 0.90) - 1))
    return {
        "count": len(values),
        "min": values[0],
        "max": values[-1],
        "mean": float(mean(values)),
        "median": float(median(values)),
        "p90": values[p90_index],
    }


def _metric_fields(labels: Sequence[int], probabilities: Sequence[float], threshold: float) -> dict[str, Any]:
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("Metric inputs must be non-empty and have equal lengths.")
    if not 0 <= float(threshold) <= 1:
        raise ValueError("Decision threshold must be between 0 and 1.")
    if any(label not in (0, 1) for label in labels):
        raise ValueError("Gold labels must be binary.")
    if any(not math.isfinite(float(probability)) or not 0 <= float(probability) <= 1 for probability in probabilities):
        raise ValueError("Model probabilities must be finite values between 0 and 1.")
    predictions = [int(float(probability) >= threshold) for probability in probabilities]
    metrics = evaluate_predictions(labels, predictions, probabilities)
    tn, fp, fn, tp = metrics.confusion_matrix[0][0], metrics.confusion_matrix[0][1], metrics.confusion_matrix[1][0], metrics.confusion_matrix[1][1]
    return {
        "sample_count": len(labels),
        "class_distribution": {"safe": int(labels.count(0)), "phishing": int(labels.count(1))},
        "confusion_matrix": {"labels": ["safe", "phishing"], "matrix": metrics.confusion_matrix},
        "accuracy": metrics.accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "false_positive_count": int(fp),
        "false_negative_count": int(fn),
        "false_positive_rate": metrics.false_positive_rate,
        "false_negative_rate": metrics.false_negative_rate,
        "roc_auc": metrics.roc_auc,
        "pr_auc": metrics.pr_auc,
        "brier_score": metrics.brier_score,
        "threshold": float(threshold),
        "predictions": predictions,
        "counts": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)},
    }


def build_evaluation_report(
    records: Sequence[GoldEvaluationInput],
    probabilities: Sequence[float],
    threshold: float,
) -> dict[str, Any]:
    """Return metrics and privacy-safe reports without including evaluation text."""

    labels = [record.label for record in records]
    metrics = _metric_fields(labels, probabilities, threshold)
    predictions = metrics.pop("predictions")
    probability_values = [float(value) for value in probabilities]
    probability_summaries: dict[str, Any] = {
        "overall": _probability_summary(probability_values),
        "by_expected_label": {
            name: _probability_summary([probability_values[index] for index, record in enumerate(records) if record.label == label])
            for name, label in GOLD_LABEL_MAPPING.items()
        },
    }
    source_indices: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        source_indices[record.source_dataset].append(index)
    per_source: list[dict[str, Any]] = []
    for source_dataset in sorted(source_indices):
        indices = source_indices[source_dataset]
        source_metrics = _metric_fields(
            [labels[index] for index in indices],
            [probability_values[index] for index in indices],
            threshold,
        )
        source_metrics.pop("predictions")
        per_source.append({"source_dataset": source_dataset, **source_metrics})

    misclassifications = [
        {
            "sample_id": record.sample_id,
            "expected_label": record.label_name,
            "predicted_label": "phishing" if predictions[index] else "safe",
            "phishing_probability": probability_values[index],
            "threshold": float(threshold),
        }
        for index, record in enumerate(records)
        if predictions[index] != record.label
    ]
    return {
        **metrics,
        "probability_summaries": probability_summaries,
        "per_source_results": per_source,
        "misclassification_count": len(misclassifications),
        "misclassifications": misclassifications,
    }


def privacy_safe_artifact_text(text: str) -> bool:
    """Check report text for paths, raw PII, URLs, headers, or secret-like data."""

    if _privacy_violations(text):
        return False
    if re.search(r"(?i)(?:[A-Za-z]:\\|[A-Za-z]:/|/Users/|/home/|/tmp/|/var/)", text):
        return False
    return True
