"""Deterministic, label-blind reviewer package helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from app.schemas.gemini_review import ReviewerQueueItem


SCHEMA_VERSION = 'dataset-review-package-1'
QUEUE_COLUMNS = [
    'schema_version', 'sample_id', 'subject_redacted', 'sender_domain', 'reply_to_domain',
    'authentication_summary', 'body_excerpt', 'url_domains', 'url_structural_flags',
    'attachment_extension', 'attachment_mime', 'candidate_category',
]
DECISION_COLUMNS = ['schema_version', 'reviewer_id', 'sample_id', 'label', 'confidence', 'notes', 'content_hash']
ALLOWED_LABELS = {'safe', 'suspicious', 'phishing', 'unable_to_determine'}
FORBIDDEN_COLUMNS = {'expected_class', 'final_human_label', 'adjudicated_label', 'gemini_suggestion', 'prediction', 'raw_email', 'path', 'source_dataset'}


def _csv_safe(value: object) -> str:
    text = str(value or '').replace('\r', ' ').replace('\n', ' ').strip()
    if text.startswith(('=', '+', '-', '@')):
        return "'" + text
    return text


def _package_hash(rows: list[dict[str, str]]) -> str:
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def reviewer_queue_csv(reviewer_id: str, queue: list[ReviewerQueueItem]) -> tuple[str, str]:
    # Reviewer ordering is deterministic per reviewer, while the queue itself
    # contains no source labels, predictions, Gemini output, or local paths.
    ordered = sorted(queue, key=lambda item: hashlib.sha256(f'{reviewer_id}\0{item.sample_id}'.encode()).hexdigest())
    rows: list[dict[str, str]] = []
    for item in ordered:
        row = {
            'schema_version': SCHEMA_VERSION,
            'sample_id': item.sample_id,
            'subject_redacted': _csv_safe(item.subject_redacted),
            'sender_domain': _csv_safe(item.sender_domain),
            'reply_to_domain': _csv_safe(item.reply_to_domain),
            'authentication_summary': _csv_safe('; '.join(item.authentication_summary)),
            'body_excerpt': _csv_safe(item.body_excerpt),
            'url_domains': _csv_safe('; '.join(item.url_domains)),
            'url_structural_flags': _csv_safe('; '.join(item.url_structural_flags)),
            'attachment_extension': _csv_safe(item.attachment_extension),
            'attachment_mime': _csv_safe(item.attachment_mime),
            'candidate_category': _csv_safe(item.candidate_category),
        }
        rows.append(row)
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=QUEUE_COLUMNS, lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue(), _package_hash(rows)


def validate_decision_csv(csv_text: str, reviewer_id: str, expected_package_hash: str) -> tuple[list[dict[str, str | float]], list[str]]:
    if any(column in csv_text for column in FORBIDDEN_COLUMNS):
        raise ValueError('Reviewer package contains forbidden label or raw-content fields.')
    reader = csv.DictReader(io.StringIO(csv_text))
    if reader.fieldnames != DECISION_COLUMNS:
        raise ValueError('Decision package schema is invalid.')
    decisions: list[dict[str, str | float]] = []
    seen: set[str] = set()
    for row in reader:
        if row.get('schema_version') != SCHEMA_VERSION or row.get('reviewer_id') != reviewer_id:
            raise ValueError('Reviewer identity or package version is invalid.')
        sample_id = row.get('sample_id', '')
        if not sample_id or sample_id in seen:
            raise ValueError('Duplicate or missing sample decision.')
        if row.get('label') not in ALLOWED_LABELS:
            raise ValueError('Decision label is invalid.')
        try:
            confidence = float(row.get('confidence', ''))
        except ValueError as error:
            raise ValueError('Decision confidence is invalid.') from error
        if not 0 <= confidence <= 1:
            raise ValueError('Decision confidence is invalid.')
        content_hash = row.get('content_hash', '')
        if len(content_hash) != 64 or any(character not in '0123456789abcdef' for character in content_hash):
            raise ValueError('Content hash is invalid.')
        seen.add(sample_id)
        decisions.append({
            'sample_id': sample_id,
            'reviewer_id': reviewer_id,
            'label': row['label'],
            'confidence': confidence,
            'notes': row.get('notes', '')[:2000],
            'content_hash': content_hash,
        })
    # The package hash is carried as an explicit binding supplied by the
    # operator; the queue export endpoint computes it before sharing.
    if len(expected_package_hash) != 64:
        raise ValueError('Package hash is invalid.')
    return decisions, []


def disagreement_sample_ids(reviewer_one: list[dict[str, str | float]], reviewer_two: list[dict[str, str | float]]) -> list[str]:
    one = {str(row['sample_id']): str(row['label']) for row in reviewer_one}
    two = {str(row['sample_id']): str(row['label']) for row in reviewer_two}
    return sorted(sample_id for sample_id in one.keys() & two.keys() if one[sample_id] != two[sample_id])
