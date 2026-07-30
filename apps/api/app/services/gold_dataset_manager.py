"""Phase III persistent gold-dataset curation manager.

This service is deliberately separate from the production inference pipeline.
It stores reviewer metadata and decisions in the ignored local evaluation
SQLite database, computes agreement, and writes privacy-safe exports/reports.
"""

from __future__ import annotations

import csv
import hashlib
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
    GoldDatasetDashboard,
    GoldDatasetReview,
    GoldDatasetReviewInput,
    GoldReviewState,
    LabelQuality,
    ReviewerDecisionInput,
)


SCHEMA_VERSION = 'gold-dataset-manager-1'
EXPORT_VERSION = 'gold-dataset-v1'


class GoldDatasetError(ValueError):
    pass


class DuplicateReviewError(GoldDatasetError):
    pass


class InvalidStateTransitionError(GoldDatasetError):
    pass


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
        supplied_path = path is not None
        configured = Path(path or get_settings().dataset_review_storage_path)
        if not configured.is_absolute():
            configured = Path.cwd() / configured
        self.path = configured.resolve()
        if not supplied_path:
            private_root = (Path(__file__).resolve().parents[4] / 'services' / 'ml' / 'evaluation' / 'private').resolve()
            if not self.path.is_relative_to(private_root):
                raise GoldDatasetError('Gold dataset storage must remain under the ignored private evaluation directory.')
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
                """
            )
            connection.execute(
                'INSERT OR IGNORE INTO gold_dataset_schema(schema_version, created_at) VALUES (?, ?)',
                (SCHEMA_VERSION, _now()),
            )

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
                connection.execute('UPDATE gold_reviews SET state=?, updated_at=? WHERE review_id=?', (new_state.value, now, review_id_text))
                self._insert_audit(connection, review_id_text, reviewer_name, row['phishing_label'], row['phishing_label'], row['reviewer_confidence'], row['reviewer_confidence'], reason, old_state.value, new_state.value)
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
        destination = self._output_dir(output_dir, 'reports/gold_standard/phase_iii')
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

    def _insert_audit(self, connection: sqlite3.Connection, review_id: str, reviewer: str, old_label: str | None, new_label: str | None, old_confidence: float | None, new_confidence: float | None, reason: str, old_state: str | None, new_state: str | None) -> None:
        connection.execute(
            """
            INSERT INTO gold_review_audit(
                review_id, timestamp, reviewer, old_label, new_label,
                old_confidence, new_confidence, reason, old_state, new_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (review_id, _now(), reviewer, old_label, new_label, old_confidence, new_confidence, _privacy_safe_text(reason, 600), old_state, new_state),
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

    def _output_dir(self, output_dir: str | Path | None, default_relative: str) -> Path:
        destination = Path(output_dir or default_relative)
        if not destination.is_absolute():
            destination = Path.cwd() / destination
        return destination.resolve()

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
