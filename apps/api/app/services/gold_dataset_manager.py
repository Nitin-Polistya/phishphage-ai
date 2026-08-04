"""Phase III persistent gold-dataset curation manager.

This service is deliberately separate from the production inference pipeline.
It stores reviewer metadata and decisions in the ignored local evaluation
SQLite database, computes agreement, and writes privacy-safe exports/reports.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

from app.core.settings import get_settings
from app.schemas.gemini_review import ReviewLabel
from app.schemas.gold_dataset import (
    AgreementStatistics,
    AuditTrailEntry,
    BatchImportFormat,
    BatchImportRequest,
    BatchReviewResponse,
    BulkFailure,
    BulkLabelRequest,
    BulkOperationResponse,
    BulkReviewSettingsRequest,
    BulkTransitionRequest,
    DatasetReviewQueueItem,
    DatasetReviewQueueResponse,
    GoldDatasetDashboard,
    GoldDatasetReview,
    GoldDatasetReviewInput,
    GoldReviewState,
    LabelQuality,
    ReviewerDecisionInput,
    SourceClaimedLabel,
)
from app.services.private_storage import resolve_private_evaluation_path


SCHEMA_VERSION = 'gold-dataset-manager-2'
EXPORT_VERSION = 'gold-dataset-v1'
MAX_PREVIEW_BODY = 800
_BATCH_FIELD_ALIASES = {
    'source_sample_id': 'source_sample_id',
    'source_dataset': 'source_dataset',
    'dataset': 'source_dataset',
    'campaign_id': 'campaign_id',
    'campaign_identifier': 'campaign_id',
    'language': 'language',
    'source_claimed_label': 'source_claimed_label',
    'source_label': 'source_claimed_label',
    'claimed_label': 'source_claimed_label',
    'claimed_source_label': 'source_claimed_label',
    'label': 'source_claimed_label',
    'subject': 'subject',
    'sanitized_subject': 'subject',
    'body_excerpt': 'body_excerpt',
    'sanitized_body_excerpt': 'body_excerpt',
    'sender_domain': 'sender_domain',
    'reply_to_domain': 'reply_to_domain',
    'authentication_summary': 'authentication_summary',
    'url_domains': 'url_domains',
    'url_structural_flags': 'url_structural_flags',
    'attachment_metadata': 'attachment_metadata',
    'attachment_extension': 'attachment_extension',
    'attachment_mime': 'attachment_mime',
    'normalized_content_hash': 'normalized_content_hash',
    'sample_hash': 'sample_hash',
    'source_identifier': 'source_identifier',
}


class GoldDatasetError(ValueError):
    pass


class DuplicateReviewError(GoldDatasetError):
    pass


class InvalidStateTransitionError(GoldDatasetError):
    pass


class BatchImportError(GoldDatasetError):
    def __init__(self, message: str, errors: list[dict[str, object]] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class GoldDatasetManager:
    _allowed_transitions: dict[GoldReviewState, set[GoldReviewState]] = {
        GoldReviewState.pending: {GoldReviewState.reviewed, GoldReviewState.rejected, GoldReviewState.archived},
        GoldReviewState.reviewed: {GoldReviewState.needs_second_review, GoldReviewState.approved, GoldReviewState.rejected, GoldReviewState.archived},
        GoldReviewState.needs_second_review: {GoldReviewState.approved, GoldReviewState.rejected, GoldReviewState.archived},
        GoldReviewState.approved: {GoldReviewState.archived},
        GoldReviewState.rejected: {GoldReviewState.archived},
        GoldReviewState.archived: set(),
    }

    def __init__(self, path: str | Path | None = None) -> None:
        configured = path if path is not None else get_settings().dataset_review_storage_path
        try:
            self.path = resolve_private_evaluation_path(
                configured,
                error_message='Gold dataset storage must remain under the ignored private evaluation directory.',
            )
        except ValueError as error:
            raise GoldDatasetError(str(error)) from None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gold_dataset_schema (
                    schema_version TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gold_reviews (
                    review_id TEXT PRIMARY KEY,
                    sample_hash TEXT NOT NULL,
                    normalized_content_hash TEXT NOT NULL,
                    source_dataset TEXT NOT NULL,
                    source_sample_id TEXT NOT NULL,
                    source_identifier TEXT NOT NULL,
                    campaign_identifier TEXT NOT NULL,
                    review_timestamp TEXT NOT NULL,
                    reviewer_name TEXT NOT NULL,
                    language TEXT NOT NULL,
                    phishing_label TEXT NOT NULL,
                    label_quality TEXT NOT NULL,
                    reviewer_confidence REAL NOT NULL,
                    review_notes TEXT NOT NULL,
                    gemini_recommendation TEXT,
                    gemini_reasoning_summary TEXT,
                    accepted_gemini_recommendation INTEGER,
                    requires_second_review INTEGER NOT NULL DEFAULT 0,
                    review_version TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(sample_hash, normalized_content_hash, campaign_identifier, source_identifier)
                );
                CREATE INDEX IF NOT EXISTS idx_gold_reviews_state ON gold_reviews(state);
                CREATE INDEX IF NOT EXISTS idx_gold_reviews_source ON gold_reviews(source_dataset);
                CREATE TABLE IF NOT EXISTS gold_reviewer_decisions (
                    decision_id TEXT PRIMARY KEY,
                    review_id TEXT NOT NULL,
                    reviewer_name TEXT NOT NULL,
                    phishing_label TEXT NOT NULL,
                    label_quality TEXT NOT NULL,
                    reviewer_confidence REAL NOT NULL,
                    review_notes TEXT NOT NULL,
                    requires_second_review INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE(review_id, reviewer_name),
                    FOREIGN KEY(review_id) REFERENCES gold_reviews(review_id)
                );
                CREATE TABLE IF NOT EXISTS gold_reviewer_agreement (
                    agreement_id TEXT PRIMARY KEY,
                    reviewer_a TEXT NOT NULL,
                    reviewer_b TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    agreement_count INTEGER NOT NULL,
                    disagreement_count INTEGER NOT NULL,
                    agreement_rate REAL NOT NULL,
                    cohen_kappa REAL NOT NULL,
                    reviewer_consistency_json TEXT NOT NULL,
                    conflict_statistics_json TEXT NOT NULL,
                    computed_at TEXT NOT NULL,
                    statistics_version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gold_review_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    review_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    old_label TEXT,
                    new_label TEXT,
                    old_confidence REAL,
                    new_confidence REAL,
                    reason TEXT NOT NULL,
                    old_state TEXT,
                    new_state TEXT,
                    FOREIGN KEY(review_id) REFERENCES gold_reviews(review_id)
                );
                CREATE TRIGGER IF NOT EXISTS gold_audit_no_update
                    BEFORE UPDATE ON gold_review_audit
                    BEGIN SELECT RAISE(ABORT, 'Gold audit records are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS gold_audit_no_delete
                    BEFORE DELETE ON gold_review_audit
                    BEGIN SELECT RAISE(ABORT, 'Gold audit records are immutable'); END;
                CREATE TABLE IF NOT EXISTS dataset_review_batches (
                    batch_id TEXT PRIMARY KEY,
                    source_format TEXT NOT NULL,
                    imported_by TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    idempotency_key TEXT UNIQUE
                );
                CREATE TABLE IF NOT EXISTS dataset_review_items (
                    item_id TEXT PRIMARY KEY,
                    batch_id TEXT NOT NULL,
                    row_number INTEGER NOT NULL,
                    source_sample_id TEXT NOT NULL,
                    source_dataset TEXT NOT NULL,
                    source_identifier TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    language TEXT NOT NULL,
                    source_claimed_label TEXT NOT NULL,
                    subject_preview TEXT NOT NULL,
                    body_excerpt TEXT NOT NULL,
                    sender_domain TEXT NOT NULL,
                    reply_to_domain TEXT NOT NULL,
                    authentication_summary_json TEXT NOT NULL,
                    url_domains_json TEXT NOT NULL,
                    url_structural_flags_json TEXT NOT NULL,
                    attachment_metadata TEXT NOT NULL,
                    sample_hash TEXT NOT NULL,
                    normalized_content_hash TEXT NOT NULL,
                    duplicate_status TEXT NOT NULL,
                    duplicate_reasons_json TEXT NOT NULL,
                    current_review_id TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(batch_id, row_number),
                    UNIQUE(batch_id, source_sample_id),
                    FOREIGN KEY(batch_id) REFERENCES dataset_review_batches(batch_id)
                );
                CREATE INDEX IF NOT EXISTS idx_dataset_review_items_batch ON dataset_review_items(batch_id, row_number);
                CREATE INDEX IF NOT EXISTS idx_dataset_review_items_claimed ON dataset_review_items(source_claimed_label);
                CREATE TABLE IF NOT EXISTS gold_bulk_operations (
                    bulk_operation_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    idempotency_key TEXT UNIQUE,
                    request_hash TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(connection, 'gold_review_audit', 'bulk_operation_id', 'TEXT')
            self._ensure_column(connection, 'gold_review_audit', 'batch_id', 'TEXT')
            self._ensure_column(connection, 'gold_review_audit', 'operation', 'TEXT')
            connection.execute(
                'INSERT OR IGNORE INTO gold_dataset_schema(schema_version, created_at) VALUES (?, ?)',
                (SCHEMA_VERSION, _now()),
            )

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row['name'] for row in connection.execute(f'PRAGMA table_info({table})').fetchall()}
        if column not in columns:
            connection.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')

    def import_batch(self, request: BatchImportRequest) -> BatchReviewResponse:
        """Import sanitized metadata only; source labels never become human labels."""
        settings = get_settings()
        content_hash = hashlib.sha256(f'{request.format.value}\0{request.content}'.encode('utf-8')).hexdigest()
        rows = _parse_batch_content(request.format, request.content)
        if len(rows) > settings.dataset_review_max_batch_size:
            raise BatchImportError(f'Batch exceeds the configured limit of {settings.dataset_review_max_batch_size} rows.', [
                {'row_number': settings.dataset_review_max_batch_size + 1, 'code': 'batch_size_exceeded', 'message': 'The batch contains too many rows.'},
            ])
        normalized_rows = [_normalize_batch_row(row, index) for index, row in enumerate(rows, start=1)]
        _validate_batch_duplicates(normalized_rows)
        batch_id = request.batch_id or f'batch-{uuid4()}'
        imported_at = _now()
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                existing = None
                if request.idempotency_key:
                    existing = connection.execute(
                        'SELECT batch_id, content_hash FROM dataset_review_batches WHERE idempotency_key=?',
                        (request.idempotency_key,),
                    ).fetchone()
                if existing is not None:
                    if existing['content_hash'] != content_hash:
                        raise BatchImportError('The idempotency key was already used for different batch content.')
                    connection.commit()
                    return self._get_batch_response(connection, existing['batch_id'])
                existing_batch = connection.execute('SELECT content_hash FROM dataset_review_batches WHERE batch_id=?', (batch_id,)).fetchone()
                if existing_batch is not None:
                    if existing_batch['content_hash'] != content_hash:
                        raise BatchImportError('The requested batch ID already exists with different content.')
                    connection.commit()
                    return self._get_batch_response(connection, batch_id)
                duplicate_info = self._existing_duplicate_info(connection, normalized_rows)
                connection.execute(
                    'INSERT INTO dataset_review_batches(batch_id, source_format, imported_by, content_hash, imported_at, idempotency_key) VALUES (?, ?, ?, ?, ?, ?)',
                    (batch_id, request.format.value, _safe_identifier(request.imported_by), content_hash, imported_at, request.idempotency_key),
                )
                for row in normalized_rows:
                    reasons = duplicate_info.get(row['row_number'], [])
                    connection.execute(
                        """
                        INSERT INTO dataset_review_items(
                            item_id, batch_id, row_number, source_sample_id, source_dataset, source_identifier,
                            campaign_id, language, source_claimed_label, subject_preview, body_excerpt,
                            sender_domain, reply_to_domain, authentication_summary_json, url_domains_json,
                            url_structural_flags_json, attachment_metadata, sample_hash, normalized_content_hash,
                            duplicate_status, duplicate_reasons_json, current_review_id, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(uuid4()), batch_id, row['row_number'], row['source_sample_id'], row['source_dataset'],
                            row['source_identifier'], row['campaign_id'], row['language'], row['source_claimed_label'],
                            row['subject'], row['body_excerpt'], row['sender_domain'], row['reply_to_domain'],
                            json.dumps(row['authentication_summary'], sort_keys=True), json.dumps(row['url_domains'], sort_keys=True),
                            json.dumps(row['url_structural_flags'], sort_keys=True), row['attachment_metadata'], row['sample_hash'],
                            row['normalized_content_hash'], 'duplicate' if reasons else 'clear', json.dumps(reasons, sort_keys=True), None, imported_at,
                        ),
                    )
                connection.commit()
                return self._get_batch_response(connection, batch_id)
            except Exception:
                connection.rollback()
                raise

    def get_batch(self, batch_id: str) -> BatchReviewResponse:
        with self._connect() as connection:
            return self._get_batch_response(connection, batch_id)

    def list_queue(
        self,
        *,
        page: int = 1,
        page_size: int = 100,
        source_label: SourceClaimedLabel | None = None,
        human_label: ReviewLabel | None = None,
        state: GoldReviewState | None = None,
        language: str | None = None,
        source_dataset: str | None = None,
        campaign: str | None = None,
        duplicate_status: str | None = None,
        second_review_required: bool | None = None,
        search: str | None = None,
    ) -> DatasetReviewQueueResponse:
        page = max(1, page)
        page_size = min(100, max(1, page_size))
        clauses = ['1=1']
        params: list[object] = []
        if source_label:
            clauses.append('i.source_claimed_label=?'); params.append(source_label.value)
        if human_label:
            clauses.append('g.phishing_label=?'); params.append(human_label.value)
        if state:
            clauses.append("COALESCE(g.state, 'pending')=?"); params.append(state.value)
        if language:
            clauses.append('i.language=?'); params.append(_safe_identifier(language))
        if source_dataset:
            clauses.append('i.source_dataset=?'); params.append(_safe_identifier(source_dataset))
        if campaign:
            clauses.append('i.campaign_id=?'); params.append(_safe_identifier(campaign))
        if duplicate_status:
            clauses.append('i.duplicate_status=?'); params.append(duplicate_status)
        if second_review_required is not None:
            clauses.append('COALESCE(g.requires_second_review, 0)=?'); params.append(int(second_review_required))
        if search:
            query = _safe_identifier(search)
            clauses.append('(i.source_sample_id LIKE ? OR i.source_identifier LIKE ? OR i.campaign_id LIKE ?)')
            params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])
        where = ' AND '.join(clauses)
        with self._connect() as connection:
            total = int(connection.execute(
                f'SELECT COUNT(*) AS count FROM dataset_review_items i LEFT JOIN gold_reviews g ON g.review_id=i.current_review_id WHERE {where}',
                tuple(params),
            ).fetchone()['count'])
            rows = connection.execute(
                f'''SELECT i.*, g.review_id AS linked_review_id, g.phishing_label AS human_label,
                    g.state AS human_state, g.reviewer_confidence AS human_confidence,
                    g.requires_second_review AS human_second_review
                    FROM dataset_review_items i LEFT JOIN gold_reviews g ON g.review_id=i.current_review_id
                    WHERE {where} ORDER BY i.batch_id, i.row_number LIMIT ? OFFSET ?''',
                (*params, page_size, (page - 1) * page_size),
            ).fetchall()
            return DatasetReviewQueueResponse(items=[self._queue_item(connection, row) for row in rows], total=total, page=page, page_size=page_size)

    def bulk_label(self, request: BulkLabelRequest) -> BulkOperationResponse:
        operation = 'bulk_label'
        self._assert_bulk_limit(request.item_ids)
        request_hash = _request_hash(request.model_dump(mode='json'))
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                prior = self._prior_operation(connection, request.idempotency_key, request_hash)
                if prior is not None:
                    connection.commit(); return prior
                operation_id = uuid4()
                item_rows, failures = self._bulk_item_rows(connection, request.item_ids)
                failures.extend(self._label_failures(connection, item_rows, request))
                if failures:
                    result = _bulk_result(operation_id, operation, len(request.item_ids), 0, 0, len(failures), True, failures, [])
                    self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                    connection.commit(); return result
                changed: list[sqlite3.Row] = []
                for item in item_rows:
                    review = self._linked_review(connection, item)
                    now = _now()
                    next_state = GoldReviewState.needs_second_review.value if request.requires_second_review else GoldReviewState.reviewed.value
                    if review is None:
                        review_id = uuid4()
                        self._insert_review_from_batch(connection, item, review_id, request, next_state, now)
                        connection.execute('UPDATE dataset_review_items SET current_review_id=? WHERE item_id=?', (str(review_id), item['item_id']))
                        self._insert_audit(connection, str(review_id), request.reviewer_name, None, request.label.value, None, request.confidence, request.reason, None, next_state, str(operation_id), item['batch_id'], operation)
                    else:
                        old_state = review['state']
                        old_label = review['phishing_label']
                        old_confidence = float(review['reviewer_confidence'])
                        connection.execute(
                            'UPDATE gold_reviews SET phishing_label=?, label_quality=?, reviewer_confidence=?, review_notes=?, requires_second_review=?, state=?, updated_at=? WHERE review_id=?',
                            (request.label.value, request.label_quality.value, request.confidence, _privacy_safe_text(request.reason, 2000), int(request.requires_second_review), next_state, now, review['review_id']),
                        )
                        self._upsert_primary_decision(connection, review['review_id'], request, now)
                        self._insert_audit(connection, review['review_id'], request.reviewer_name, old_label, request.label.value, old_confidence, request.confidence, request.reason, old_state, next_state, str(operation_id), item['batch_id'], operation)
                    changed.append(item)
                result = _bulk_result(operation_id, operation, len(request.item_ids), len(changed), 0, 0, True, [], [self._queue_item_by_id(connection, item['item_id']) for item in changed])
                self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                connection.commit(); return result
            except Exception:
                connection.rollback(); raise

    def bulk_review_settings(self, request: BulkReviewSettingsRequest) -> BulkOperationResponse:
        self._assert_bulk_limit(request.item_ids)
        if request.confidence is None and request.requires_second_review is None:
            raise GoldDatasetError('At least one review setting must be provided.')
        operation = 'bulk_review_settings'
        request_hash = _request_hash(request.model_dump(mode='json'))
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                prior = self._prior_operation(connection, request.idempotency_key, request_hash)
                if prior is not None:
                    connection.commit(); return prior
                operation_id = uuid4()
                item_rows, failures = self._bulk_item_rows(connection, request.item_ids)
                for item in item_rows:
                    review = self._linked_review(connection, item)
                    if review is None:
                        failures.append(BulkFailure(item_id=item['item_id'], reason='A human label is required before changing review settings.'))
                    elif review['state'] in {GoldReviewState.approved.value, GoldReviewState.archived.value}:
                        failures.append(BulkFailure(item_id=item['item_id'], reason='Approved or archived reviews cannot be changed.'))
                if failures:
                    result = _bulk_result(operation_id, operation, len(request.item_ids), 0, 0, len(failures), True, failures, [])
                    self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                    connection.commit(); return result
                changed = []
                for item in item_rows:
                    review = self._linked_review(connection, item)
                    assert review is not None
                    old_confidence = float(review['reviewer_confidence'])
                    next_confidence = request.confidence if request.confidence is not None else old_confidence
                    old_second = bool(review['requires_second_review'])
                    next_second = request.requires_second_review if request.requires_second_review is not None else old_second
                    old_state = review['state']
                    next_state = old_state
                    if request.requires_second_review is True and old_state in {GoldReviewState.pending.value, GoldReviewState.reviewed.value}:
                        next_state = GoldReviewState.needs_second_review.value
                    elif request.requires_second_review is False and old_state == GoldReviewState.needs_second_review.value:
                        next_state = GoldReviewState.reviewed.value
                    connection.execute('UPDATE gold_reviews SET reviewer_confidence=?, requires_second_review=?, state=?, updated_at=? WHERE review_id=?', (next_confidence, int(next_second), next_state, _now(), review['review_id']))
                    self._insert_audit(connection, review['review_id'], request.reviewer_name, review['phishing_label'], review['phishing_label'], old_confidence, next_confidence, request.reason, old_state, next_state, str(operation_id), item['batch_id'], operation)
                    changed.append(item)
                result = _bulk_result(operation_id, operation, len(request.item_ids), len(changed), 0, 0, True, [], [self._queue_item_by_id(connection, item['item_id']) for item in changed])
                self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                connection.commit(); return result
            except Exception:
                connection.rollback(); raise

    def bulk_transition(self, request: BulkTransitionRequest) -> BulkOperationResponse:
        self._assert_bulk_limit(request.item_ids)
        if request.new_state == GoldReviewState.pending:
            raise GoldDatasetError('Bulk transitions cannot move a reviewed item back to pending.')
        operation = f'bulk_transition_{request.new_state.value}'
        request_hash = _request_hash(request.model_dump(mode='json'))
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                prior = self._prior_operation(connection, request.idempotency_key, request_hash)
                if prior is not None:
                    connection.commit(); return prior
                operation_id = uuid4()
                item_rows, failures = self._bulk_item_rows(connection, request.item_ids)
                eligible: list[sqlite3.Row] = []
                for item in item_rows:
                    review = self._linked_review(connection, item)
                    failure = self._transition_failure(connection, item, review, request.new_state)
                    if failure:
                        failures.append(BulkFailure(item_id=item['item_id'], reason=failure))
                    else:
                        eligible.append(item)
                if failures and not request.allow_partial:
                    result = _bulk_result(operation_id, operation, len(request.item_ids), 0, 0, len(failures), True, failures, [])
                    self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                    connection.commit(); return result
                changed = []
                for item in eligible:
                    review = self._linked_review(connection, item)
                    assert review is not None
                    old_state = review['state']
                    connection.execute('UPDATE gold_reviews SET state=?, requires_second_review=?, updated_at=? WHERE review_id=?', (request.new_state.value, int(request.new_state == GoldReviewState.needs_second_review or review['requires_second_review']), _now(), review['review_id']))
                    self._insert_audit(connection, review['review_id'], request.reviewer_name, review['phishing_label'], review['phishing_label'], review['reviewer_confidence'], review['reviewer_confidence'], request.reason, old_state, request.new_state.value, str(operation_id), item['batch_id'], operation)
                    changed.append(item)
                result = _bulk_result(operation_id, operation, len(request.item_ids), len(changed), len(changed) if request.new_state == GoldReviewState.approved else 0, len(request.item_ids) - len(changed), request.allow_partial or not failures, failures, [self._queue_item_by_id(connection, item['item_id']) for item in changed])
                self._save_operation(connection, operation_id, operation, request.idempotency_key, request_hash, result)
                connection.commit(); return result
            except Exception:
                connection.rollback(); raise

    def _get_batch_response(self, connection: sqlite3.Connection, batch_id: str) -> BatchReviewResponse:
        batch = connection.execute('SELECT * FROM dataset_review_batches WHERE batch_id=?', (batch_id,)).fetchone()
        if batch is None:
            raise GoldDatasetError('Dataset review batch was not found.')
        rows = connection.execute('SELECT * FROM dataset_review_items WHERE batch_id=? ORDER BY row_number', (batch_id,)).fetchall()
        return BatchReviewResponse(
            batch_id=batch['batch_id'], source_format=BatchImportFormat(batch['source_format']), imported_count=len(rows),
            duplicate_count=sum(row['duplicate_status'] != 'clear' for row in rows), imported_at=_parse_time(batch['imported_at']),
            items=[self._queue_item(connection, row) for row in rows],
            warnings=['Source labels are advisory provenance only; no row was automatically human-labeled or approved.'],
        )

    def _existing_duplicate_info(self, connection: sqlite3.Connection, rows: list[dict[str, object]]) -> dict[int, list[str]]:
        result: dict[int, list[str]] = {}
        for row in rows:
            reasons: list[str] = []
            if connection.execute('SELECT 1 FROM gold_reviews WHERE sample_hash=? LIMIT 1', (row['sample_hash'],)).fetchone():
                reasons.append('existing_gold_sample_hash')
            if connection.execute('SELECT 1 FROM gold_reviews WHERE normalized_content_hash=? LIMIT 1', (row['normalized_content_hash'],)).fetchone():
                reasons.append('existing_gold_normalized_content_hash')
            if connection.execute('SELECT 1 FROM gold_reviews WHERE source_sample_id=? LIMIT 1', (row['source_sample_id'],)).fetchone():
                reasons.append('existing_gold_source_sample_id')
            if connection.execute('SELECT 1 FROM dataset_review_items WHERE sample_hash=? OR normalized_content_hash=? LIMIT 1', (row['sample_hash'], row['normalized_content_hash'])).fetchone():
                reasons.append('existing_queue_hash')
            if reasons:
                result[int(row['row_number'])] = sorted(set(reasons))
        return result

    def _bulk_item_rows(self, connection: sqlite3.Connection, item_ids: list[UUID]) -> tuple[list[sqlite3.Row], list[BulkFailure]]:
        unique_ids = list(dict.fromkeys(str(item_id) for item_id in item_ids))
        failures: list[BulkFailure] = []
        if len(unique_ids) != len(item_ids):
            failures.extend(BulkFailure(item_id=UUID(item_id), reason='Duplicate item IDs were supplied.') for item_id in unique_ids if item_ids.count(UUID(item_id)) > 1)
        rows: list[sqlite3.Row] = []
        for item_id in unique_ids:
            row = connection.execute('SELECT * FROM dataset_review_items WHERE item_id=?', (item_id,)).fetchone()
            if row is None:
                failures.append(BulkFailure(item_id=UUID(item_id), reason='The selected queue item was not found.'))
            else:
                rows.append(row)
        return rows, failures

    @staticmethod
    def _assert_bulk_limit(item_ids: list[UUID]) -> None:
        if len(item_ids) > get_settings().dataset_review_max_bulk_items:
            raise GoldDatasetError(f'Bulk operation exceeds the configured limit of {get_settings().dataset_review_max_bulk_items} items.')

    def _linked_review(self, connection: sqlite3.Connection, item: sqlite3.Row) -> sqlite3.Row | None:
        review_id = item['current_review_id']
        return connection.execute('SELECT * FROM gold_reviews WHERE review_id=?', (review_id,)).fetchone() if review_id else None

    def _label_failures(self, connection: sqlite3.Connection, rows: list[sqlite3.Row], request: BulkLabelRequest) -> list[BulkFailure]:
        failures: list[BulkFailure] = []
        for item in rows:
            review = self._linked_review(connection, item)
            if item['duplicate_status'] != 'clear':
                failures.append(BulkFailure(item_id=item['item_id'], reason='Duplicate candidates must be inspected and skipped; no duplicate gold review is created.'))
            elif review is not None and review['state'] in {GoldReviewState.approved.value, GoldReviewState.archived.value}:
                failures.append(BulkFailure(item_id=item['item_id'], reason='Approved or archived reviews cannot be relabeled.'))
        return failures

    def _transition_failure(self, connection: sqlite3.Connection, item: sqlite3.Row, review: sqlite3.Row | None, new_state: GoldReviewState) -> str | None:
        if review is None:
            return 'A human label is required before a state transition.'
        old_state = GoldReviewState(review['state'])
        if new_state not in self._allowed_transitions[old_state]:
            return f'Invalid state transition: {old_state.value} -> {new_state.value}.'
        if new_state == GoldReviewState.approved:
            if item['duplicate_status'] != 'clear':
                return 'Duplicate items cannot be approved.'
            try:
                self._assert_approval_ready(connection, review)
            except GoldDatasetError as error:
                return str(error)
        return None

    def _insert_review_from_batch(self, connection: sqlite3.Connection, item: sqlite3.Row, review_id: UUID, request: BulkLabelRequest, state: str, now: str) -> None:
        connection.execute(
            """
            INSERT INTO gold_reviews(
                review_id, sample_hash, normalized_content_hash, source_dataset, source_sample_id,
                source_identifier, campaign_identifier, review_timestamp, reviewer_name, language,
                phishing_label, label_quality, reviewer_confidence, review_notes,
                gemini_recommendation, gemini_reasoning_summary, accepted_gemini_recommendation,
                requires_second_review, review_version, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?)
            """,
            (
                str(review_id), item['sample_hash'], item['normalized_content_hash'], item['source_dataset'], item['source_sample_id'],
                item['source_identifier'], item['campaign_id'], now, request.reviewer_name, item['language'], request.label.value,
                request.label_quality.value, request.confidence, _privacy_safe_text(request.reason, 2000), int(request.requires_second_review),
                'gold-dataset-v1', state, now, now,
            ),
        )
        connection.execute(
            'INSERT INTO gold_reviewer_decisions(decision_id, review_id, reviewer_name, phishing_label, label_quality, reviewer_confidence, review_notes, requires_second_review, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (str(uuid4()), str(review_id), request.reviewer_name, request.label.value, request.label_quality.value, request.confidence, _privacy_safe_text(request.reason, 2000), int(request.requires_second_review), now),
        )

    def _upsert_primary_decision(self, connection: sqlite3.Connection, review_id: str, request: BulkLabelRequest, now: str) -> None:
        existing = connection.execute('SELECT decision_id FROM gold_reviewer_decisions WHERE review_id=? AND reviewer_name=?', (review_id, request.reviewer_name)).fetchone()
        if existing:
            connection.execute('UPDATE gold_reviewer_decisions SET phishing_label=?, label_quality=?, reviewer_confidence=?, review_notes=?, requires_second_review=?, created_at=? WHERE decision_id=?', (request.label.value, request.label_quality.value, request.confidence, _privacy_safe_text(request.reason, 2000), int(request.requires_second_review), now, existing['decision_id']))
        else:
            connection.execute('INSERT INTO gold_reviewer_decisions(decision_id, review_id, reviewer_name, phishing_label, label_quality, reviewer_confidence, review_notes, requires_second_review, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (str(uuid4()), review_id, request.reviewer_name, request.label.value, request.label_quality.value, request.confidence, _privacy_safe_text(request.reason, 2000), int(request.requires_second_review), now))

    def _prior_operation(self, connection: sqlite3.Connection, idempotency_key: str | None, request_hash: str) -> BulkOperationResponse | None:
        if not idempotency_key:
            return None
        row = connection.execute('SELECT request_hash, result_json FROM gold_bulk_operations WHERE idempotency_key=?', (idempotency_key,)).fetchone()
        if row is None:
            return None
        if row['request_hash'] != request_hash:
            raise GoldDatasetError('The idempotency key was already used for a different operation.')
        return BulkOperationResponse.model_validate(json.loads(row['result_json']))

    @staticmethod
    def _save_operation(connection: sqlite3.Connection, operation_id: UUID, operation: str, idempotency_key: str | None, request_hash: str, result: BulkOperationResponse) -> None:
        connection.execute('INSERT INTO gold_bulk_operations(bulk_operation_id, operation, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)', (str(operation_id), operation, idempotency_key, request_hash, json.dumps(result.model_dump(mode='json'), sort_keys=True), _now()))

    def create_review(self, review: GoldDatasetReviewInput) -> GoldDatasetReview:
        review_id = review.review_id or uuid4()
        now = _now()
        review_timestamp = review.review_timestamp.isoformat() if review.review_timestamp else now
        if review.state == GoldReviewState.approved:
            raise GoldDatasetError('A new review cannot start in approved state.')
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                self._assert_no_duplicate(connection, review)
                connection.execute(
                    """
                    INSERT INTO gold_reviews(
                        review_id, sample_hash, normalized_content_hash, source_dataset, source_sample_id,
                        source_identifier, campaign_identifier, review_timestamp, reviewer_name, language,
                        phishing_label, label_quality, reviewer_confidence, review_notes,
                        gemini_recommendation, gemini_reasoning_summary, accepted_gemini_recommendation,
                        requires_second_review, review_version, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(review_id), review.sample_hash, review.normalized_content_hash, review.source_dataset,
                        review.source_sample_id, review.source_identifier, review.campaign_identifier,
                        review_timestamp, review.reviewer_name, review.language, review.phishing_label.value,
                        review.label_quality.value, review.reviewer_confidence, _privacy_safe_text(review.review_notes, 2000),
                        review.gemini_recommendation.value if review.gemini_recommendation else None,
                        _privacy_safe_text(review.gemini_reasoning_summary, 1200), _bool_int(review.accepted_gemini_recommendation),
                        int(review.requires_second_review), review.review_version, review.state.value, now, now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO gold_reviewer_decisions(
                        decision_id, review_id, reviewer_name, phishing_label, label_quality,
                        reviewer_confidence, review_notes, requires_second_review, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(uuid4()), str(review_id), review.reviewer_name, review.phishing_label.value, review.label_quality.value, review.reviewer_confidence, _privacy_safe_text(review.review_notes, 2000), int(review.requires_second_review), now),
                )
                self._insert_audit(connection, str(review_id), review.reviewer_name, None, review.phishing_label.value, None, review.reviewer_confidence, 'Initial human review created.', None, review.state.value)
                connection.commit()
                return self._get_review(connection, review_id)
            except sqlite3.IntegrityError as error:
                connection.rollback()
                if 'UNIQUE' in str(error).upper():
                    raise DuplicateReviewError('A duplicate reviewed sample already exists.') from None
                raise
            except Exception:
                connection.rollback()
                raise

    def add_reviewer_decision(self, review_id: UUID | str, decision: ReviewerDecisionInput) -> GoldDatasetReview:
        review_id_text = str(review_id)
        now = _now()
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                row = connection.execute('SELECT * FROM gold_reviews WHERE review_id=?', (review_id_text,)).fetchone()
                if row is None:
                    raise GoldDatasetError('Gold review does not exist.')
                if row['state'] == GoldReviewState.archived.value:
                    raise GoldDatasetError('Archived reviews cannot be changed.')
                connection.execute(
                    """
                    INSERT INTO gold_reviewer_decisions(
                        decision_id, review_id, reviewer_name, phishing_label, label_quality,
                        reviewer_confidence, review_notes, requires_second_review, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(uuid4()), review_id_text, decision.reviewer_name, decision.phishing_label.value, decision.label_quality.value, decision.reviewer_confidence, _privacy_safe_text(decision.review_notes, 2000), int(decision.requires_second_review), now),
                )
                next_state = GoldReviewState.needs_second_review.value if row['state'] in {GoldReviewState.pending.value, GoldReviewState.reviewed.value} else row['state']
                connection.execute(
                    'UPDATE gold_reviews SET requires_second_review=1, state=?, updated_at=? WHERE review_id=?',
                    (next_state, now, review_id_text),
                )
                self._insert_audit(connection, review_id_text, decision.reviewer_name, row['phishing_label'], decision.phishing_label.value, row['reviewer_confidence'], decision.reviewer_confidence, decision.reason, row['state'], next_state)
                connection.commit()
                return self._get_review(connection, UUID(review_id_text))
            except sqlite3.IntegrityError:
                connection.rollback()
                raise GoldDatasetError('This reviewer has already submitted a decision for the sample.') from None
            except Exception:
                connection.rollback()
                raise

    def transition_state(self, review_id: UUID | str, reviewer_name: str, new_state: GoldReviewState, reason: str) -> GoldDatasetReview:
        review_id_text = str(review_id)
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                row = connection.execute('SELECT * FROM gold_reviews WHERE review_id=?', (review_id_text,)).fetchone()
                if row is None:
                    raise GoldDatasetError('Gold review does not exist.')
                old_state = GoldReviewState(row['state'])
                if new_state not in self._allowed_transitions[old_state]:
                    raise InvalidStateTransitionError(f'Invalid state transition: {old_state.value} -> {new_state.value}.')
                if new_state == GoldReviewState.approved:
                    self._assert_approval_ready(connection, row)
                now = _now()
                next_second_review = int(row['requires_second_review']) or int(new_state == GoldReviewState.needs_second_review)
                connection.execute('UPDATE gold_reviews SET state=?, requires_second_review=?, updated_at=? WHERE review_id=?', (new_state.value, next_second_review, now, review_id_text))
                self._insert_audit(connection, review_id_text, reviewer_name, row['phishing_label'], row['phishing_label'], row['reviewer_confidence'], row['reviewer_confidence'], reason, old_state.value, new_state.value, None, None, 'transition')
                connection.commit()
                return self._get_review(connection, UUID(review_id_text))
            except Exception:
                connection.rollback()
                raise

    def revise_review(self, review_id: UUID | str, reviewer_name: str, *, phishing_label: ReviewLabel | None = None, reviewer_confidence: float | None = None, review_notes: str | None = None, reason: str) -> GoldDatasetReview:
        review_id_text = str(review_id)
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                row = connection.execute('SELECT * FROM gold_reviews WHERE review_id=?', (review_id_text,)).fetchone()
                if row is None:
                    raise GoldDatasetError('Gold review does not exist.')
                if row['state'] in {GoldReviewState.approved.value, GoldReviewState.archived.value}:
                    raise GoldDatasetError('Approved or archived reviews require a new review version.')
                old_label = row['phishing_label']
                old_confidence = float(row['reviewer_confidence'])
                next_label = phishing_label.value if phishing_label else old_label
                next_confidence = reviewer_confidence if reviewer_confidence is not None else old_confidence
                next_notes = _privacy_safe_text(review_notes, 2000) if review_notes is not None else row['review_notes']
                connection.execute(
                    'UPDATE gold_reviews SET phishing_label=?, reviewer_confidence=?, review_notes=?, updated_at=? WHERE review_id=?',
                    (next_label, next_confidence, next_notes, _now(), review_id_text),
                )
                self._insert_audit(connection, review_id_text, reviewer_name, old_label, next_label, old_confidence, next_confidence, reason, row['state'], row['state'])
                connection.commit()
                return self._get_review(connection, UUID(review_id_text))
            except Exception:
                connection.rollback()
                raise

    def get_review(self, review_id: UUID | str) -> GoldDatasetReview:
        with self._connect() as connection:
            return self._get_review(connection, UUID(str(review_id)))

    def list_reviews(self, state: GoldReviewState | None = None) -> list[GoldDatasetReview]:
        with self._connect() as connection:
            rows = connection.execute('SELECT * FROM gold_reviews' + (' WHERE state=?' if state else '') + ' ORDER BY created_at, review_id', ((state.value,) if state else ())).fetchall()
            return [self._row_to_review(row) for row in rows]

    def get_audit_trail(self, review_id: UUID | str) -> list[AuditTrailEntry]:
        with self._connect() as connection:
            rows = connection.execute('SELECT * FROM gold_review_audit WHERE review_id=? ORDER BY audit_id', (str(review_id),)).fetchall()
            return [
                AuditTrailEntry(
                    audit_id=row['audit_id'], review_id=row['review_id'], timestamp=_parse_time(row['timestamp']), reviewer=row['reviewer'],
                    old_label=row['old_label'], new_label=row['new_label'], old_confidence=row['old_confidence'], new_confidence=row['new_confidence'],
                    reason=row['reason'], old_state=row['old_state'], new_state=row['new_state'],
                    bulk_operation_id=row['bulk_operation_id'], batch_id=row['batch_id'], operation=row['operation'],
                ) for row in rows
            ]

    def compute_agreement(self, reviewer_a: str, reviewer_b: str) -> AgreementStatistics:
        if reviewer_a == reviewer_b:
            raise GoldDatasetError('Agreement requires two distinct human reviewers.')
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                'SELECT review_id, reviewer_name, phishing_label FROM gold_reviewer_decisions WHERE reviewer_name IN (?, ?)',
                (reviewer_a, reviewer_b),
            ).fetchall()
            decisions: dict[str, dict[str, str]] = defaultdict(dict)
            for row in rows:
                decisions[row['review_id']][row['reviewer_name']] = row['phishing_label']
            pairs = [(values[reviewer_a], values[reviewer_b]) for values in decisions.values() if reviewer_a in values and reviewer_b in values]
            sample_count = len(pairs)
            agreement_count = sum(left == right for left, right in pairs)
            disagreement_count = sample_count - agreement_count
            agreement_rate = agreement_count / sample_count if sample_count else 0.0
            kappa = _cohen_kappa(pairs)
            conflicts = Counter(f'{left}|{right}' for left, right in pairs if left != right)
            consistency = {reviewer_a: agreement_rate, reviewer_b: agreement_rate}
            stats = AgreementStatistics(
                agreement_id=uuid4(), reviewer_a=reviewer_a, reviewer_b=reviewer_b,
                sample_count=sample_count, agreement_count=agreement_count, disagreement_count=disagreement_count,
                agreement_rate=agreement_rate, cohen_kappa=kappa, reviewer_consistency=consistency,
                conflict_statistics=dict(conflicts), computed_at=_parse_time(_now()), statistics_version='agreement-v1',
            )
            connection.execute(
                """
                INSERT INTO gold_reviewer_agreement(
                    agreement_id, reviewer_a, reviewer_b, sample_count, agreement_count,
                    disagreement_count, agreement_rate, cohen_kappa, reviewer_consistency_json,
                    conflict_statistics_json, computed_at, statistics_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (str(stats.agreement_id), reviewer_a, reviewer_b, stats.sample_count, stats.agreement_count, stats.disagreement_count, stats.agreement_rate, stats.cohen_kappa, json.dumps(stats.reviewer_consistency, sort_keys=True), json.dumps(stats.conflict_statistics, sort_keys=True), stats.computed_at.isoformat(), stats.statistics_version),
            )
            return stats

    def latest_agreement(self) -> AgreementStatistics | None:
        with self._connect() as connection:
            row = connection.execute('SELECT * FROM gold_reviewer_agreement ORDER BY computed_at DESC LIMIT 1').fetchone()
            if row is None:
                return None
            return AgreementStatistics(
                agreement_id=row['agreement_id'], reviewer_a=row['reviewer_a'], reviewer_b=row['reviewer_b'], sample_count=row['sample_count'], agreement_count=row['agreement_count'], disagreement_count=row['disagreement_count'], agreement_rate=row['agreement_rate'], cohen_kappa=row['cohen_kappa'], reviewer_consistency=json.loads(row['reviewer_consistency_json']), conflict_statistics=json.loads(row['conflict_statistics_json']), computed_at=_parse_time(row['computed_at']), statistics_version=row['statistics_version'],
            )

    def dashboard(self) -> GoldDatasetDashboard:
        with self._connect() as connection:
            rows = connection.execute('SELECT * FROM gold_reviews ORDER BY created_at').fetchall()
            total = len(rows)
            completed_states = {GoldReviewState.reviewed.value, GoldReviewState.needs_second_review.value, GoldReviewState.approved.value, GoldReviewState.rejected.value, GoldReviewState.archived.value}
            completed = sum(row['state'] in completed_states for row in rows)
            queue = Counter(row['state'] for row in rows)
            confidence_bins = Counter(_confidence_bin(float(row['reviewer_confidence'])) for row in rows)
            second_count = sum(bool(row['requires_second_review']) for row in rows)
            return GoldDatasetDashboard(
                total_samples=total, review_completion=completed / total if total else 0.0,
                approved_samples=queue[GoldReviewState.approved.value],
                review_queue={state.value: queue[state.value] for state in GoldReviewState},
                reviewer_agreement=self.latest_agreement(),
                label_distribution=dict(Counter(row['phishing_label'] for row in rows)),
                language_distribution=dict(Counter(row['language'] for row in rows)),
                confidence_distribution=dict(confidence_bins),
                source_distribution=dict(Counter(row['source_dataset'] for row in rows)),
                second_review_count=second_count,
            )

    def export_gold_dataset(self, output_dir: str | Path | None = None) -> dict[str, object]:
        destination = self._output_dir(output_dir, 'services/ml/evaluation/private/gold_dataset_exports')
        destination.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM gold_reviews WHERE state='approved' ORDER BY review_id").fetchall()
        records = [_privacy_safe_export_record(row) for row in rows]
        jsonl_path = destination / 'gold_dataset_v1.jsonl'
        summary_path = destination / 'gold_dataset_summary.json'
        stats_path = destination / 'gold_dataset_statistics.md'
        jsonl_path.write_text(''.join(json.dumps(record, sort_keys=True, ensure_ascii=True) + '\n' for record in records), encoding='utf-8')
        summary = self._summary(records)
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')
        stats_path.write_text(_statistics_markdown(summary), encoding='utf-8')
        return {'directory': destination, 'files': [jsonl_path, summary_path, stats_path], 'exported_samples': len(records)}

    def generate_reports(self, output_dir: str | Path | None = None) -> dict[str, Path]:
        destination = self._output_dir(output_dir, 'services/ml/evaluation/private/gold_dataset_reports')
        destination.mkdir(parents=True, exist_ok=True)
        dashboard = self.dashboard()
        agreement = dashboard.reviewer_agreement
        review_statistics = dashboard.model_dump(mode='json')
        quality_metrics = {
            'total_samples': dashboard.total_samples,
            'review_completion': dashboard.review_completion,
            'approved_samples': dashboard.approved_samples,
            'second_review_count': dashboard.second_review_count,
            'agreement_rate': agreement.agreement_rate if agreement else None,
            'cohen_kappa': agreement.cohen_kappa if agreement else None,
        }
        paths = {
            'review_statistics': destination / 'review_statistics.json',
            'agreement_report': destination / 'agreement_report.md',
            'quality_metrics': destination / 'quality_metrics.json',
            'label_distribution': destination / 'label_distribution.csv',
            'gold_dataset_summary': destination / 'gold_dataset_summary.md',
        }
        paths['review_statistics'].write_text(json.dumps(review_statistics, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')
        paths['quality_metrics'].write_text(json.dumps(quality_metrics, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')
        with paths['label_distribution'].open('w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(['label', 'count'])
            writer.writerows(sorted(dashboard.label_distribution.items()))
        paths['agreement_report'].write_text(_agreement_markdown(agreement), encoding='utf-8')
        paths['gold_dataset_summary'].write_text(_summary_markdown(dashboard), encoding='utf-8')
        return paths

    def _assert_no_duplicate(self, connection: sqlite3.Connection, review: GoldDatasetReviewInput) -> None:
        row = connection.execute(
            """
            SELECT review_id FROM gold_reviews
            WHERE sample_hash=? OR normalized_content_hash=?
               OR (campaign_identifier=? AND source_identifier=?)
            LIMIT 1
            """,
            (review.sample_hash, review.normalized_content_hash, review.campaign_identifier, review.source_identifier),
        ).fetchone()
        if row is not None:
            raise DuplicateReviewError('A duplicate reviewed sample already exists.')

    def _assert_approval_ready(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
        if row['phishing_label'] == ReviewLabel.unable_to_determine.value:
            raise GoldDatasetError('Indeterminate labels cannot be approved.')
        if row['requires_second_review']:
            decisions = connection.execute('SELECT reviewer_name, phishing_label FROM gold_reviewer_decisions WHERE review_id=?', (row['review_id'],)).fetchall()
            if len(decisions) < 2:
                raise GoldDatasetError('A second human review is required before approval.')
            if len({decision['phishing_label'] for decision in decisions}) > 1:
                raise GoldDatasetError('Conflicting human labels require adjudication before approval.')

    def _insert_audit(
        self,
        connection: sqlite3.Connection,
        review_id: str,
        reviewer: str,
        old_label: str | None,
        new_label: str | None,
        old_confidence: float | None,
        new_confidence: float | None,
        reason: str,
        old_state: str | None,
        new_state: str | None,
        bulk_operation_id: str | None = None,
        batch_id: str | None = None,
        operation: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO gold_review_audit(
                review_id, timestamp, reviewer, old_label, new_label,
                old_confidence, new_confidence, reason, old_state, new_state,
                bulk_operation_id, batch_id, operation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (review_id, _now(), reviewer, old_label, new_label, old_confidence, new_confidence, _privacy_safe_text(reason, 600), old_state, new_state, bulk_operation_id, batch_id, operation),
        )

    def _get_review(self, connection: sqlite3.Connection, review_id: UUID) -> GoldDatasetReview:
        row = connection.execute('SELECT * FROM gold_reviews WHERE review_id=?', (str(review_id),)).fetchone()
        if row is None:
            raise GoldDatasetError('Gold review does not exist.')
        return self._row_to_review(row)

    @staticmethod
    def _row_to_review(row: sqlite3.Row) -> GoldDatasetReview:
        return GoldDatasetReview(
            review_id=row['review_id'], sample_hash=row['sample_hash'], normalized_content_hash=row['normalized_content_hash'], source_dataset=row['source_dataset'], source_sample_id=row['source_sample_id'], source_identifier=row['source_identifier'], campaign_identifier=row['campaign_identifier'], review_timestamp=_parse_time(row['review_timestamp']), reviewer_name=row['reviewer_name'], language=row['language'], phishing_label=row['phishing_label'], label_quality=row['label_quality'], reviewer_confidence=row['reviewer_confidence'], review_notes=row['review_notes'], gemini_recommendation=row['gemini_recommendation'], gemini_reasoning_summary=row['gemini_reasoning_summary'], accepted_gemini_recommendation=_int_bool(row['accepted_gemini_recommendation']), requires_second_review=bool(row['requires_second_review']), review_version=row['review_version'], created_at=_parse_time(row['created_at']), updated_at=_parse_time(row['updated_at']), state=row['state'],
        )

    def _queue_item(self, connection: sqlite3.Connection, row: sqlite3.Row) -> DatasetReviewQueueItem:
        review_id = row['linked_review_id'] if 'linked_review_id' in row.keys() else row['current_review_id']
        human_label = row['human_label'] if 'human_label' in row.keys() else None
        state = row['human_state'] if 'human_state' in row.keys() else None
        confidence = row['human_confidence'] if 'human_confidence' in row.keys() else None
        requires_second = bool(row['human_second_review']) if 'human_second_review' in row.keys() and row['human_second_review'] is not None else False
        second_complete = False
        if review_id:
            decision_rows = connection.execute('SELECT phishing_label FROM gold_reviewer_decisions WHERE review_id=? ORDER BY created_at', (review_id,)).fetchall()
            second_complete = len(decision_rows) >= 2 and len({decision['phishing_label'] for decision in decision_rows}) == 1
        return DatasetReviewQueueItem(
            item_id=row['item_id'], batch_id=row['batch_id'], row_number=row['row_number'], source_sample_id=row['source_sample_id'],
            source_dataset=row['source_dataset'], campaign_id=row['campaign_id'], language=row['language'],
            source_claimed_label=row['source_claimed_label'], current_human_label=human_label, state=state or GoldReviewState.pending.value,
            confidence=confidence, duplicate_status=row['duplicate_status'], duplicate_reasons=json.loads(row['duplicate_reasons_json']),
            second_review_required=requires_second, second_review_complete=second_complete, review_id=review_id,
            subject_preview=row['subject_preview'], body_excerpt=row['body_excerpt'], sender_domain=row['sender_domain'],
            reply_to_domain=row['reply_to_domain'], authentication_summary=json.loads(row['authentication_summary_json']),
            url_domains=json.loads(row['url_domains_json']), url_structural_flags=json.loads(row['url_structural_flags_json']),
            attachment_metadata=row['attachment_metadata'],
        )

    def _queue_item_by_id(self, connection: sqlite3.Connection, item_id: str) -> DatasetReviewQueueItem:
        row = connection.execute(
            '''SELECT i.*, g.review_id AS linked_review_id, g.phishing_label AS human_label,
               g.state AS human_state, g.reviewer_confidence AS human_confidence,
               g.requires_second_review AS human_second_review
               FROM dataset_review_items i LEFT JOIN gold_reviews g ON g.review_id=i.current_review_id
               WHERE i.item_id=?''',
            (str(item_id),),
        ).fetchone()
        if row is None:
            raise GoldDatasetError('Dataset review queue item was not found.')
        return self._queue_item(connection, row)

    def _output_dir(self, output_dir: str | Path | None, default_relative: str) -> Path:
        destination = output_dir if output_dir is not None else default_relative
        return resolve_private_evaluation_path(
            destination,
            error_message='Gold dataset output must remain under the ignored private evaluation directory.',
        )

    @staticmethod
    def _summary(records: list[dict[str, object]]) -> dict[str, object]:
        return {
            'export_version': EXPORT_VERSION,
            'generated_at': _now(),
            'record_count': len(records),
            'label_distribution': dict(Counter(str(record['phishing_label']) for record in records)),
            'language_distribution': dict(Counter(str(record['language']) for record in records)),
            'source_distribution': dict(Counter(str(record['source_dataset']) for record in records)),
        }


def _parse_batch_content(source_format: BatchImportFormat, content: str) -> list[dict[str, object]]:
    if _PATH_RE.search(content) or re.search(r'(?i)(?:raw_email|raw_content|attachment_path|file_path|message-id|received:)', content):
        raise BatchImportError('Raw file references, private paths, and raw headers are not accepted in batch imports.')
    errors: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    if source_format == BatchImportFormat.csv:
        try:
            reader = csv.DictReader(io.StringIO(content, newline=''), strict=True)
            if not reader.fieldnames:
                raise ValueError('CSV must include a header row.')
            for row_number, row in enumerate(reader, start=2):
                if None in row.values():
                    errors.append({'row_number': row_number, 'code': 'malformed_row', 'message': 'CSV row has a missing field.'})
                elif any(value is None for value in row.values()):
                    errors.append({'row_number': row_number, 'code': 'malformed_row', 'message': 'CSV row is malformed.'})
                else:
                    rows.append({str(key): value for key, value in row.items()})
        except (csv.Error, ValueError) as error:
            errors.append({'row_number': 1, 'code': 'malformed_csv', 'message': str(error)[:200]})
    else:
        for row_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                errors.append({'row_number': row_number, 'code': 'malformed_jsonl', 'message': 'Blank JSONL lines are not accepted.'})
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError('Each JSONL line must be an object.')
                rows.append(value)
            except (json.JSONDecodeError, ValueError) as error:
                errors.append({'row_number': row_number, 'code': 'malformed_jsonl', 'message': str(error)[:200]})
    if errors:
        raise BatchImportError('The batch contains malformed rows.', errors)
    if not rows:
        raise BatchImportError('The batch must contain at least one row.')
    return rows


def _normalize_batch_row(row: dict[str, object], row_number: int) -> dict[str, object]:
    canonical: dict[str, object] = {}
    for key, value in row.items():
        normalized_key = str(key).strip().lower().replace(' ', '_').replace('-', '_')
        target = _BATCH_FIELD_ALIASES.get(normalized_key)
        if target is None:
            raise BatchImportError('The batch contains an unsupported field.', [{'row_number': row_number, 'code': 'unsupported_field', 'message': 'The row contains an unsupported field.', 'field': normalized_key[:80]}])
        if target in canonical and canonical[target] not in ('', None) and value not in ('', None):
            raise BatchImportError('The row contains conflicting aliases.', [{'row_number': row_number, 'code': 'conflicting_fields', 'message': 'Only one alias may provide a field value.', 'field': target}])
        if value not in ('', None):
            canonical[target] = value
    source_sample_id = _required_identifier(canonical.get('source_sample_id'), row_number, 'source_sample_id')
    source_dataset = _identifier(canonical.get('source_dataset'), 'unknown-source', row_number, 'source_dataset')
    source_identifier = _identifier(canonical.get('source_identifier'), source_sample_id, row_number, 'source_identifier')
    campaign_id = _identifier(canonical.get('campaign_id'), 'campaign-undetermined', row_number, 'campaign_id')
    language = _identifier(canonical.get('language'), 'und', row_number, 'language')
    source_claimed_label = _source_label(canonical.get('source_claimed_label'), row_number)
    subject = _safe_batch_text(canonical.get('subject'), 300, row_number, 'subject')
    body_excerpt = _safe_batch_text(canonical.get('body_excerpt'), MAX_PREVIEW_BODY, row_number, 'body_excerpt')
    sender_domain = _domain(canonical.get('sender_domain'), row_number, 'sender_domain')
    reply_to_domain = _domain(canonical.get('reply_to_domain'), row_number, 'reply_to_domain')
    authentication_summary = _string_list(canonical.get('authentication_summary'), row_number, 'authentication_summary', 10)
    url_domains = [_domain(value, row_number, 'url_domains') for value in _string_list(canonical.get('url_domains'), row_number, 'url_domains', 30)]
    url_structural_flags = [_safe_batch_text(value, 80, row_number, 'url_structural_flags') for value in _string_list(canonical.get('url_structural_flags'), row_number, 'url_structural_flags', 30)]
    attachment_parts = [_safe_batch_text(canonical.get('attachment_metadata'), 180, row_number, 'attachment_metadata')]
    if canonical.get('attachment_extension') not in (None, ''):
        attachment_parts.append(f"extension:{_safe_batch_text(canonical.get('attachment_extension'), 40, row_number, 'attachment_extension')}")
    if canonical.get('attachment_mime') not in (None, ''):
        attachment_parts.append(f"mime:{_safe_batch_text(canonical.get('attachment_mime'), 120, row_number, 'attachment_mime')}")
    attachment_metadata = '; '.join(part for part in attachment_parts if part)
    content_identity = {
        'subject': subject.casefold(), 'body_excerpt': re.sub(r'\s+', ' ', body_excerpt).strip().casefold(),
        'sender_domain': sender_domain, 'reply_to_domain': reply_to_domain, 'authentication_summary': authentication_summary,
        'url_domains': url_domains, 'url_structural_flags': url_structural_flags, 'attachment_metadata': attachment_metadata,
    }
    normalized_content_hash = _hash_value(canonical.get('normalized_content_hash'), content_identity)
    sample_hash = _hash_value(canonical.get('sample_hash'), {'normalized_content_hash': normalized_content_hash, 'source_sample_id': source_sample_id})
    return {
        'row_number': row_number, 'source_sample_id': source_sample_id, 'source_dataset': source_dataset,
        'source_identifier': source_identifier, 'campaign_id': campaign_id, 'language': language,
        'source_claimed_label': source_claimed_label, 'subject': subject, 'body_excerpt': body_excerpt,
        'sender_domain': sender_domain, 'reply_to_domain': reply_to_domain, 'authentication_summary': authentication_summary,
        'url_domains': url_domains, 'url_structural_flags': url_structural_flags, 'attachment_metadata': attachment_metadata,
        'sample_hash': sample_hash, 'normalized_content_hash': normalized_content_hash,
    }


def _validate_batch_duplicates(rows: list[dict[str, object]]) -> None:
    seen_ids: set[str] = set()
    seen_sample_hashes: set[str] = set()
    seen_normalized_hashes: set[str] = set()
    errors: list[dict[str, object]] = []
    for row in rows:
        row_number = int(row['row_number'])
        for key, seen, code in (
            ('source_sample_id', seen_ids, 'duplicate_sample_id'),
            ('sample_hash', seen_sample_hashes, 'duplicate_sample_hash'),
            ('normalized_content_hash', seen_normalized_hashes, 'duplicate_normalized_content_hash'),
        ):
            value = str(row[key])
            if value in seen:
                errors.append({'row_number': row_number, 'code': code, 'message': 'Duplicate stable identity within the batch.', 'field': key})
            seen.add(value)
    if errors:
        raise BatchImportError('The batch contains duplicate stable identities.', errors)


def _required_identifier(value: object, row_number: int, field: str) -> str:
    if value in (None, ''):
        raise BatchImportError('A required stable sample ID is missing.', [{'row_number': row_number, 'code': 'missing_required_field', 'message': 'source_sample_id is required.', 'field': field}])
    return _identifier(value, '', row_number, field)


def _identifier(value: object, default: str, row_number: int, field: str) -> str:
    text = str(value).strip() if value not in (None, '') else default
    if not text or _PATH_RE.search(text) or _EMAIL_RE.search(text) or re.search(r'(?i)^(?:file|https?|ftp)://', text):
        raise BatchImportError('The row contains a private path or personal identifier.', [{'row_number': row_number, 'code': 'privacy_rejected', 'message': 'Identifiers must be privacy-safe.', 'field': field}])
    cleaned = re.sub(r'[^A-Za-z0-9._:-]+', '_', text).strip('_')
    if not cleaned or len(cleaned) > 160:
        raise BatchImportError('The row contains an invalid identifier.', [{'row_number': row_number, 'code': 'invalid_identifier', 'message': 'Identifiers must be short and stable.', 'field': field}])
    return cleaned


def _source_label(value: object, row_number: int) -> str:
    normalized = str(value or 'unknown').strip().lower().replace('legitimate', 'safe')
    if normalized not in {member.value for member in SourceClaimedLabel}:
        raise BatchImportError('The row contains an unsupported source label.', [{'row_number': row_number, 'code': 'unsupported_label', 'message': 'Source labels must be safe, phishing, suspicious, or unknown.', 'field': 'source_claimed_label'}])
    return normalized


def _safe_batch_text(value: object, max_length: int, row_number: int, field: str) -> str:
    text = str(value or '').replace('\x00', ' ').strip()
    if _PATH_RE.search(text) or re.search(r'(?i)(?:attachment_path|file_path|raw_email|raw_content)', text):
        raise BatchImportError('The row contains a raw file reference.', [{'row_number': row_number, 'code': 'privacy_rejected', 'message': 'Raw file references are not accepted.', 'field': field}])
    return _privacy_safe_text(text, max_length)


def _string_list(value: object, row_number: int, field: str, max_items: int) -> list[str]:
    if value in (None, ''):
        return []
    if isinstance(value, list):
        values = value
    else:
        values = re.split(r'[,;]', str(value))
    if len(values) > max_items or any(not isinstance(item, str) for item in values):
        raise BatchImportError('The row contains too many or invalid list values.', [{'row_number': row_number, 'code': 'invalid_list', 'message': 'List fields contain only short strings.', 'field': field}])
    return [_safe_batch_text(item, 160, row_number, field) for item in values if str(item).strip()]


def _domain(value: object, row_number: int, field: str) -> str:
    text = str(value or '').strip().lower().rstrip('.')
    if not text:
        return ''
    if '@' in text or '/' in text or '?' in text or '#' in text or ':' in text or ' ' in text or len(text) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', text):
        raise BatchImportError('Only registrable-style domains are accepted.', [{'row_number': row_number, 'code': 'invalid_domain', 'message': 'Do not provide complete addresses or URLs.', 'field': field}])
    return text


def _hash_value(value: object, fallback: object) -> str:
    if value not in (None, ''):
        text = str(value).strip().lower()
        if not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', text):
            raise BatchImportError('Stable hashes must be SHA-256 values.', [{'row_number': 1, 'code': 'invalid_hash', 'message': 'A stable hash must be a SHA-256 digest.'}])
        return text.removeprefix('sha256:')
    return hashlib.sha256(json.dumps(fallback, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _request_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _bulk_result(operation_id: UUID, operation: str, requested: int, affected: int, approved: int, skipped: int, atomic: bool, failures: list[BulkFailure], items: list[DatasetReviewQueueItem]) -> BulkOperationResponse:
    return BulkOperationResponse(bulk_operation_id=operation_id, operation=operation, requested_count=requested, affected_count=affected, approved_count=approved, skipped_count=skipped, atomic=atomic, failures=failures, items=items)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def _bool_int(value: bool | None) -> int | None:
    return None if value is None else int(value)


def _int_bool(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _cohen_kappa(pairs: list[tuple[str, str]]) -> float:
    if not pairs:
        return 0.0
    observed = sum(left == right for left, right in pairs) / len(pairs)
    left_counts = Counter(left for left, _ in pairs)
    right_counts = Counter(right for _, right in pairs)
    labels = set(left_counts) | set(right_counts)
    expected = sum((left_counts[label] / len(pairs)) * (right_counts[label] / len(pairs)) for label in labels)
    if expected == 1.0:
        return 1.0 if observed == 1.0 else 0.0
    return max(-1.0, min(1.0, (observed - expected) / (1.0 - expected)))


def _confidence_bin(value: float) -> str:
    if value < 0.25:
        return '0.00-0.24'
    if value < 0.50:
        return '0.25-0.49'
    if value < 0.75:
        return '0.50-0.74'
    return '0.75-1.00'


_EMAIL_RE = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
_URL_RE = re.compile(r'(?i)\b(?:https?|ftp|javascript|data|file|blob|chrome):[^\s<>]+')
_PHONE_RE = re.compile(r'(?<!\w)\+?\d[\d .()\-]{7,}\d(?!\w)')
_PATH_RE = re.compile(r'(?i)(?:[A-Za-z]:\\|/Users/|/home/|/tmp/|/var/|file://)[^\s]+')
_HEADER_RE = re.compile(r'(?im)^(?:from|to|cc|bcc|subject|received|message-id|authentication-results|return-path):.*$')


def _privacy_safe_text(value: str | None, max_length: int = 600) -> str:
    text = (value or '').replace('\r', ' ').replace('\n', ' ').strip()
    text = _HEADER_RE.sub('[header removed]', text)
    text = _URL_RE.sub('[URL removed]', text)
    text = _EMAIL_RE.sub('[address removed]', text)
    text = _PHONE_RE.sub('[phone removed]', text)
    text = _PATH_RE.sub('[path removed]', text)
    text = re.sub(r'(?is)<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text)[:max_length].strip()


def _safe_identifier(value: str, *, digest: bool = False) -> str:
    if digest:
        return f'sha256:{hashlib.sha256(value.encode("utf-8")).hexdigest()}'
    cleaned = _privacy_safe_text(value, 160)
    return re.sub(r'[^A-Za-z0-9._:-]+', '_', cleaned).strip('_') or 'redacted'


def _privacy_safe_export_record(row: sqlite3.Row) -> dict[str, object]:
    return {
        'export_version': EXPORT_VERSION,
        'review_id': row['review_id'],
        'sample_hash': _safe_identifier(str(row['sample_hash']), digest=True),
        'source_dataset': _safe_identifier(str(row['source_dataset']), digest=True),
        'source_sample_id_digest': _safe_identifier(row['source_sample_id'], digest=True),
        'campaign_identifier': _safe_identifier(row['campaign_identifier'], digest=True),
        'language': _safe_identifier(row['language']),
        'phishing_label': row['phishing_label'],
        'label_quality': row['label_quality'],
        'reviewer_confidence': row['reviewer_confidence'],
        'review_notes': '[redacted for privacy-safe export]',
        'human_label_authority': True,
        'review_version': _safe_identifier(row['review_version']),
    }


def _statistics_markdown(summary: dict[str, object]) -> str:
    lines = ['# Gold dataset statistics', '', f"Export version: `{summary['export_version']}`", f"Records: **{summary['record_count']}**", '', '## Labels', '']
    lines.extend(f'- `{key}`: {value}' for key, value in sorted(summary['label_distribution'].items()))
    lines.extend(['', '## Languages', ''])
    lines.extend(f'- `{key}`: {value}' for key, value in sorted(summary['language_distribution'].items()))
    return '\n'.join(lines) + '\n'


def _agreement_markdown(agreement: AgreementStatistics | None) -> str:
    if agreement is None:
        return '# Reviewer agreement\n\nNo paired reviewer decisions are available.\n'
    return '\n'.join([
        '# Reviewer agreement', '', f'- Reviewers: `{agreement.reviewer_a}` and `{agreement.reviewer_b}`',
        f'- Paired samples: **{agreement.sample_count}**', f'- Agreement: **{agreement.agreement_rate:.3f}**',
        f'- Cohen\'s kappa: **{agreement.cohen_kappa:.3f}**', f'- Disagreements: **{agreement.disagreement_count}**',
        '', '## Conflict statistics', '', *[f'- `{key}`: {value}' for key, value in sorted(agreement.conflict_statistics.items())], '',
    ])


def _summary_markdown(dashboard: GoldDatasetDashboard) -> str:
    return '\n'.join([
        '# Gold dataset summary', '', f'- Total samples: **{dashboard.total_samples}**', f'- Review completion: **{dashboard.review_completion:.3f}**', f'- Approved samples: **{dashboard.approved_samples}**', f'- Needs second review: **{dashboard.second_review_count}**', '', '## Label distribution', '', *[f'- `{key}`: {value}' for key, value in sorted(dashboard.label_distribution.items())], '',
    ])
