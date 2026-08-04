from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.schemas.gemini_review import ReviewLabel
from app.schemas.gold_dataset import (
    BatchImportRequest,
    BatchImportFormat,
    BulkLabelRequest,
    BulkReviewSettingsRequest,
    BulkTransitionRequest,
    GoldDatasetReviewInput,
    GoldReviewState,
)
from app.services.gold_dataset_manager import BatchImportError, GoldDatasetManager


def private_path(tmp_path: Path, name: str) -> Path:
    return tmp_path / 'repo' / 'services' / 'ml' / 'evaluation' / 'private' / name


def csv_batch(prefix: str, label: str, count: int) -> str:
    lines = ['source_sample_id,source_dataset,source_claimed_label,campaign_id,language,subject,body_excerpt,sender_domain,sample_hash']
    for index in range(count):
        lines.append(f'{prefix}-{index},synthetic,{label},campaign-{index % 2},en,Notice {index},Sanitized preview {index},example.com,')
    return '\n'.join(lines)


def test_batch_import_preserves_advisory_source_claims_and_sanitizes_preview(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'bulk.sqlite3'))
    result = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=csv_batch('safe', 'safe', 5), imported_by='Alice'))
    assert result.imported_count == 5
    assert all(item.source_claimed_label.value == 'safe' for item in result.items)
    assert all(item.current_human_label is None and item.state == GoldReviewState.pending for item in result.items)
    assert 'source labels are advisory' in result.warnings[0].lower()

    jsonl = json.dumps({'source_sample_id': 'privacy-1', 'source_claimed_label': 'unknown', 'subject': 'Please contact person@example.com', 'body_excerpt': 'Visit https://example.com/a?token=secret'})
    privacy_result = manager.import_batch(BatchImportRequest(format=BatchImportFormat.jsonl, content=jsonl, imported_by='Alice'))
    preview = privacy_result.items[0]
    assert 'person@example.com' not in preview.subject_preview
    assert 'https://' not in preview.body_excerpt


def test_batch_validation_rejects_malformed_duplicate_and_private_rows(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'validation.sqlite3'))
    with pytest.raises(BatchImportError):
        manager.import_batch(BatchImportRequest(format=BatchImportFormat.jsonl, content='not-json', imported_by='Alice'))
    duplicate = '\n'.join([
        json.dumps({'source_sample_id': 'same', 'source_claimed_label': 'safe'}),
        json.dumps({'source_sample_id': 'same', 'source_claimed_label': 'safe'}),
    ])
    with pytest.raises(BatchImportError):
        manager.import_batch(BatchImportRequest(format=BatchImportFormat.jsonl, content=duplicate, imported_by='Alice'))
    with pytest.raises(BatchImportError):
        manager.import_batch(BatchImportRequest(format=BatchImportFormat.jsonl, content=json.dumps({'source_sample_id': 'path', 'body_excerpt': r'C:\private\message.eml'}), imported_by='Alice'))


def test_bulk_label_approval_is_explicit_atomic_and_audited(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'workflow.sqlite3'))
    batch = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=csv_batch('candidate', 'safe', 5), imported_by='Alice'))
    ids = [item.item_id for item in batch.items]
    labeled = manager.bulk_label(BulkLabelRequest(item_ids=ids[:4], label=ReviewLabel.safe, reviewer_name='Alice', reason='Human skim confirmed safe.'))
    assert labeled.affected_count == 4
    assert all(item.current_human_label == ReviewLabel.safe for item in labeled.items)
    assert labeled.items[0].state == GoldReviewState.reviewed
    approved = manager.bulk_transition(BulkTransitionRequest(item_ids=ids[:4], new_state=GoldReviewState.approved, reviewer_name='Alice', reason='Explicit approval after human review.'))
    assert approved.approved_count == 4
    queue = manager.list_queue().items
    assert next(item for item in queue if item.item_id == ids[4]).state == GoldReviewState.pending
    audit = manager.get_audit_trail(labeled.items[0].review_id)
    assert len(audit) == 2
    assert audit[0].bulk_operation_id is not None and audit[0].batch_id == batch.batch_id
    assert all(entry.operation for entry in audit)


def test_bulk_approval_fails_atomically_for_duplicate_or_second_review(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'approval.sqlite3'))
    batch = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=csv_batch('candidate', 'phishing', 2), imported_by='Alice'))
    ids = [item.item_id for item in batch.items]
    manager.bulk_label(BulkLabelRequest(item_ids=ids, label=ReviewLabel.phishing, reviewer_name='Alice', reason='Human confirmed phishing.'))
    manager.bulk_review_settings(BulkReviewSettingsRequest(item_ids=[ids[0]], reviewer_name='Alice', requires_second_review=True, reason='Needs independent second review.'))
    result = manager.bulk_transition(BulkTransitionRequest(item_ids=ids, new_state=GoldReviewState.approved, reviewer_name='Alice', reason='Attempt explicit approval.'))
    assert result.approved_count == 0
    assert len(result.failures) == 1
    assert all(item.state != GoldReviewState.approved for item in manager.list_queue().items)


def test_bulk_retry_is_idempotent_without_duplicate_audits(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'idempotency.sqlite3'))
    batch = manager.import_batch(BatchImportRequest(format=BatchImportFormat.csv, content=csv_batch('candidate', 'safe', 1), imported_by='Alice'))
    payload = BulkLabelRequest(item_ids=[batch.items[0].item_id], label=ReviewLabel.safe, reviewer_name='Alice', reason='Confirmed.', idempotency_key='label-once')
    first = manager.bulk_label(payload)
    second = manager.bulk_label(payload)
    assert first.bulk_operation_id == second.bulk_operation_id
    assert len(manager.get_audit_trail(first.items[0].review_id)) == 1


def test_existing_gold_duplicate_is_flagged_and_never_promoted(tmp_path: Path):
    manager = GoldDatasetManager(private_path(tmp_path, 'duplicate.sqlite3'))
    existing = manager.create_review(GoldDatasetReviewInput(
        sample_hash='a' * 64,
        normalized_content_hash='b' * 64,
        source_dataset='synthetic',
        source_sample_id='original',
        source_identifier='synthetic-original',
        campaign_identifier='campaign-original',
        reviewer_name='Alice',
        language='en',
        phishing_label=ReviewLabel.safe,
        label_quality='high',
        reviewer_confidence=0.9,
        review_notes='Original human review.',
    ))
    content = json.dumps({'source_sample_id': 'duplicate', 'source_dataset': 'synthetic', 'source_claimed_label': 'safe', 'sample_hash': 'a' * 64, 'normalized_content_hash': 'c' * 64})
    batch = manager.import_batch(BatchImportRequest(format=BatchImportFormat.jsonl, content=content, imported_by='Alice'))
    assert 'existing_gold_sample_hash' in batch.items[0].duplicate_reasons
    result = manager.bulk_label(BulkLabelRequest(item_ids=[batch.items[0].item_id], label=ReviewLabel.safe, reviewer_name='Alice', reason='Attempt duplicate label.'))
    assert result.affected_count == 0
    assert result.failures[0].item_id == batch.items[0].item_id
    assert manager.get_review(existing.review_id).review_id == existing.review_id
