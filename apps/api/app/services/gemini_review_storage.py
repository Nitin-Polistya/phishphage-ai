"""Small transactional SQLite store for sanitized local review provenance."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from app.core.settings import get_settings
from app.schemas.gemini_review import (
    DatasetReviewRecord,
    GeminiReviewSuggestion,
    HumanReviewRequest,
    ReviewLabel,
    ReviewMode,
    ReviewStatus,
    SanitizedReviewPayload,
)
from app.services.private_storage import resolve_private_evaluation_path

SCHEMA_VERSION = 'dataset-review-1'


class ReviewStore:
    def __init__(self, path: str | Path | None = None) -> None:
        configured = path if path is not None else get_settings().dataset_review_storage_path
        self.path = resolve_private_evaluation_path(
            configured,
            error_message='Dataset review storage must remain under the ignored private evaluation directory.',
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA foreign_keys=ON')
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS review_schema (
                    schema_version TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS review_samples (
                    sample_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    sanitized_payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    review_mode TEXT NOT NULL,
                    preliminary_label TEXT,
                    preliminary_confidence REAL,
                    preliminary_notes TEXT,
                    suggestion_json TEXT,
                    final_label TEXT,
                    final_confidence REAL,
                    reviewer_alias TEXT,
                    label_changed_after_ai INTEGER NOT NULL DEFAULT 0,
                    change_reason TEXT,
                    consent_granted INTEGER NOT NULL DEFAULT 0,
                    consent_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS human_reviews (
                    sample_id TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    reviewer_role TEXT NOT NULL,
                    label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    notes TEXT NOT NULL,
                    review_mode TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (sample_id, reviewer_role),
                    FOREIGN KEY (sample_id) REFERENCES review_samples(sample_id)
                );
                """
            )
            columns = {row['name'] for row in connection.execute('PRAGMA table_info(review_samples)').fetchall()}
            if 'consent_granted' not in columns:
                connection.execute('ALTER TABLE review_samples ADD COLUMN consent_granted INTEGER NOT NULL DEFAULT 0')
            if 'consent_at' not in columns:
                connection.execute('ALTER TABLE review_samples ADD COLUMN consent_at TEXT')
            connection.execute(
                'INSERT OR IGNORE INTO review_schema(schema_version, created_at) VALUES (?, ?)',
                (SCHEMA_VERSION, _now()),
            )

    def save_preview(self, payload: SanitizedReviewPayload) -> None:
        with self._lock, self._connect() as connection:
            now = _now()
            connection.execute('BEGIN IMMEDIATE')
            try:
                connection.execute(
                    """
                    INSERT INTO review_samples(
                        sample_id, content_hash, sanitized_payload_hash, payload_json,
                        status, review_mode, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sample_id) DO UPDATE SET
                        content_hash=excluded.content_hash,
                        sanitized_payload_hash=excluded.sanitized_payload_hash,
                        payload_json=excluded.payload_json,
                        status=CASE WHEN review_samples.sanitized_payload_hash = excluded.sanitized_payload_hash
                                    THEN review_samples.status ELSE 'unreviewed' END,
                        consent_granted=CASE WHEN review_samples.sanitized_payload_hash = excluded.sanitized_payload_hash
                                             THEN review_samples.consent_granted ELSE 0 END,
                        consent_at=CASE WHEN review_samples.sanitized_payload_hash = excluded.sanitized_payload_hash
                                        THEN review_samples.consent_at ELSE NULL END,
                        updated_at=excluded.updated_at
                    """,
                    (
                        payload.sample_id,
                        payload.sanitized_payload_hash,
                        payload.sanitized_payload_hash,
                        json.dumps(payload.model_dump(mode='json'), sort_keys=True, separators=(',', ':')),
                        ReviewStatus.unreviewed.value,
                        ReviewMode.independent.value,
                        now,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def save_suggestion(self, payload: SanitizedReviewPayload, suggestion: GeminiReviewSuggestion, *, mode: ReviewMode, reviewer_alias: str, preliminary_label: ReviewLabel | None, preliminary_confidence: float | None, preliminary_notes: str | None) -> None:
        self.save_preview(payload)
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                connection.execute(
                    """
                    UPDATE review_samples SET suggestion_json=?, status=?, review_mode=?,
                        preliminary_label=?, preliminary_confidence=?, preliminary_notes=?,
                        reviewer_alias=?, consent_granted=?, consent_at=?, updated_at=?
                        WHERE sample_id=? AND sanitized_payload_hash=?
                    """,
                    (
                        json.dumps(suggestion.model_dump(mode='json'), sort_keys=True, separators=(',', ':')),
                        ReviewStatus.gemini_suggested.value,
                        mode.value,
                        preliminary_label.value if preliminary_label else None,
                        preliminary_confidence,
                        preliminary_notes,
                        reviewer_alias,
                        1,
                        _now(),
                        _now(),
                        payload.sample_id,
                        payload.sanitized_payload_hash,
                    ),
                )
                if connection.total_changes == 0:
                    raise ValueError('Sample changed while saving the suggestion.')
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def save_human_review(self, request: HumanReviewRequest) -> DatasetReviewRecord:
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                row = connection.execute('SELECT * FROM review_samples WHERE sample_id=?', (request.sample_id,)).fetchone()
                if row is None:
                    raise ValueError('Review sample does not exist.')
                if row['content_hash'] != request.content_hash:
                    raise ValueError('Content hash does not match the review sample.')
                connection.execute(
                    """
                    INSERT INTO human_reviews(sample_id, reviewer_id, reviewer_role, label, confidence, notes, review_mode, content_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (request.sample_id, request.reviewer_id, request.reviewer_role, request.label.value, request.confidence, request.notes, request.review_mode.value, request.content_hash, _now()),
                )
                reviews = connection.execute('SELECT reviewer_role, label FROM human_reviews WHERE sample_id=?', (request.sample_id,)).fetchall()
                labels = {review['reviewer_role']: review['label'] for review in reviews}
                if 'reviewer_1' in labels and 'reviewer_2' in labels and labels['reviewer_1'] != labels['reviewer_2']:
                    status = ReviewStatus.disagreement.value
                elif 'adjudicator' in labels:
                    status = ReviewStatus.dual_reviewer_adjudicated.value if len(labels) > 1 else ReviewStatus.single_reviewer_adjudicated.value
                elif 'reviewer_2' in labels:
                    status = ReviewStatus.dual_reviewer_adjudicated.value if len(set(labels.values())) == 1 else ReviewStatus.disagreement.value
                elif 'reviewer_1' in labels:
                    status = ReviewStatus.single_reviewer_adjudicated.value
                else:
                    status = ReviewStatus.unreviewed.value
                connection.execute(
                    'UPDATE review_samples SET final_label=?, final_confidence=?, status=?, label_changed_after_ai=?, change_reason=?, updated_at=? WHERE sample_id=?',
                    (request.label.value, request.confidence, status, int(bool(row['suggestion_json'] and row['preliminary_label'] and row['preliminary_label'] != request.label.value)), request.change_reason, _now(), request.sample_id),
                )
                connection.commit()
                return self.get_record(request.sample_id, connection=connection)
            except Exception:
                connection.rollback()
                raise

    def get_record(self, sample_id: str, *, connection: sqlite3.Connection | None = None) -> DatasetReviewRecord:
        own = connection is None
        connection = connection or self._connect()
        try:
            row = connection.execute('SELECT * FROM review_samples WHERE sample_id=?', (sample_id,)).fetchone()
            if row is None:
                raise ValueError('Review sample does not exist.')
            suggestion = GeminiReviewSuggestion.model_validate(json.loads(row['suggestion_json'])) if row['suggestion_json'] else None
            return DatasetReviewRecord(
                sample_id=row['sample_id'],
                content_hash=row['content_hash'],
                sanitized_payload_hash=row['sanitized_payload_hash'],
                status=row['status'],
                review_mode=row['review_mode'],
                preliminary_human_label=row['preliminary_label'],
                preliminary_confidence=row['preliminary_confidence'],
                preliminary_notes=row['preliminary_notes'],
                gemini_suggestion=suggestion,
                final_human_label=row['final_label'],
                final_confidence=row['final_confidence'],
                reviewer_alias=row['reviewer_alias'],
                label_changed_after_ai=bool(row['label_changed_after_ai']),
                change_reason=row['change_reason'],
                updated_at=row['updated_at'],
            )
        finally:
            if own:
                connection.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
