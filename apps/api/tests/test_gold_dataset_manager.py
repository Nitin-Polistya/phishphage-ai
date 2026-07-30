from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.schemas.gemini_review import ReviewLabel
from app.schemas.gold_dataset import (
    GoldDatasetReviewInput,
    GoldReviewState,
    LabelQuality,
    ReviewerDecisionInput,
)
from app.services.gold_dataset_manager import (
    DuplicateReviewError,
    GoldDatasetManager,
    InvalidStateTransitionError,
)


def make_review(index: int, *, label: ReviewLabel = ReviewLabel.safe, requires_second_review: bool = False) -> GoldDatasetReviewInput:
    return GoldDatasetReviewInput(
        sample_hash=f'sample-hash-{index}',
        normalized_content_hash=f'normalized-hash-{index}',
        source_dataset='synthetic-source',
        source_sample_id=f'sample-{index}',
        source_identifier=f'source-{index}',
        campaign_identifier=f'campaign-{index}',
        reviewer_name='Alice',
        language='en',
        phishing_label=label,
        label_quality=LabelQuality.high,
        reviewer_confidence=0.9,
        review_notes='Human review note; no raw email is stored in the export.',
        gemini_recommendation=ReviewLabel.suspicious,
        gemini_reasoning_summary='Advisory only.',
        accepted_gemini_recommendation=False,
        requires_second_review=requires_second_review,
    )


def add_bob(manager: GoldDatasetManager, review_id: str, label: ReviewLabel, *, reason: str = 'Independent second review.'):
    return manager.add_reviewer_decision(review_id, ReviewerDecisionInput(
        reviewer_name='Bob', phishing_label=label, label_quality=LabelQuality.high,
        reviewer_confidence=0.8, review_notes='Independent human review.', reason=reason,
    ))


def test_workflow_transitions_and_invalid_transition(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    review = manager.create_review(make_review(1))
    assert review.state == GoldReviewState.pending
    reviewed = manager.transition_state(review.review_id, 'Alice', GoldReviewState.reviewed, 'Human review completed.')
    assert reviewed.state == GoldReviewState.reviewed
    with pytest.raises(InvalidStateTransitionError):
        manager.transition_state(review.review_id, 'Alice', GoldReviewState.pending, 'Attempted invalid rollback.')
    manager.transition_state(review.review_id, 'Alice', GoldReviewState.rejected, 'Insufficient evidence.')
    archived = manager.transition_state(review.review_id, 'Alice', GoldReviewState.archived, 'Archive rejected sample.')
    assert archived.state == GoldReviewState.archived


def test_duplicate_detection_uses_sample_and_normalized_identity(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    manager.create_review(make_review(1))
    with pytest.raises(DuplicateReviewError):
        manager.create_review(make_review(1))
    duplicate_hash = make_review(2).model_copy(update={'sample_hash': 'sample-hash-1'})
    with pytest.raises(DuplicateReviewError):
        manager.create_review(duplicate_hash)


def test_reviewer_agreement_kappa_and_conflict_statistics_are_persisted(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    labels = [(ReviewLabel.safe, ReviewLabel.safe), (ReviewLabel.safe, ReviewLabel.phishing), (ReviewLabel.phishing, ReviewLabel.phishing)]
    for index, (alice, bob) in enumerate(labels, start=1):
        review = manager.create_review(make_review(index, label=alice))
        add_bob(manager, str(review.review_id), bob)
        audit = manager.get_audit_trail(review.review_id)[-1]
        assert audit.old_label == alice
        assert audit.new_label == bob
        assert audit.new_confidence == 0.8
    agreement = manager.compute_agreement('Alice', 'Bob')
    assert agreement.sample_count == 3
    assert agreement.agreement_count == 2
    assert agreement.disagreement_count == 1
    assert agreement.cohen_kappa >= -1.0
    assert agreement.conflict_statistics['safe|phishing'] == 1
    assert manager.latest_agreement() is not None


def test_second_review_is_required_before_approval(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    review = manager.create_review(make_review(10, requires_second_review=True))
    manager.transition_state(review.review_id, 'Alice', GoldReviewState.reviewed, 'First review completed.')
    with pytest.raises(Exception, match='second human review'):
        manager.transition_state(review.review_id, 'Alice', GoldReviewState.approved, 'Attempted early approval.')
    add_bob(manager, str(review.review_id), ReviewLabel.safe)
    approved = manager.transition_state(review.review_id, 'Alice', GoldReviewState.approved, 'Two human labels agree.')
    assert approved.state == GoldReviewState.approved


def test_audit_trail_is_immutable_and_records_changes(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    review = manager.create_review(make_review(20))
    manager.transition_state(review.review_id, 'Alice', GoldReviewState.reviewed, 'Complete first review.')
    manager.revise_review(review.review_id, 'Alice', phishing_label=ReviewLabel.suspicious, reviewer_confidence=0.7, reason='New human evidence was reviewed.')
    entries = manager.get_audit_trail(review.review_id)
    assert len(entries) == 3
    assert entries[-1].old_label == ReviewLabel.safe
    assert entries[-1].new_label == ReviewLabel.suspicious
    with manager._connect() as connection:  # immutable trigger verification
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute('UPDATE gold_review_audit SET reason=? WHERE audit_id=?', ('tampered', entries[0].audit_id))


def test_privacy_safe_exports_and_reports(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    review = make_review(30).model_copy(update={
        'review_notes': 'From: person@example.com Subject: reset https://example.test/path Message-ID: <id@example.test> John Doe account details',
        'source_dataset': r'C:\private\inbox',
        'source_sample_id': 'person@example.com',
        'source_identifier': 'https://example.test/campaign/7',
        'campaign_identifier': 'John Doe campaign',
    })
    created = manager.create_review(review)
    manager.transition_state(created.review_id, 'Alice', GoldReviewState.reviewed, 'Human review complete.')
    manager.transition_state(created.review_id, 'Alice', GoldReviewState.approved, 'Approved by human reviewer.')
    export_dir = tmp_path / 'exports'
    exported = manager.export_gold_dataset(export_dir)
    assert exported['exported_samples'] == 1
    jsonl = (export_dir / 'gold_dataset_v1.jsonl').read_text(encoding='utf-8')
    assert 'person@example.com' not in jsonl
    assert 'https://' not in jsonl
    assert 'Message-ID' not in jsonl
    assert 'private\\inbox' not in jsonl
    assert 'John Doe' not in jsonl
    record = json.loads(jsonl)
    assert record['human_label_authority'] is True
    report_dir = tmp_path / 'reports'
    report_paths = manager.generate_reports(report_dir)
    assert {path.name for path in report_paths.values()} == {
        'review_statistics.json', 'agreement_report.md', 'quality_metrics.json', 'label_distribution.csv', 'gold_dataset_summary.md',
    }


def test_dashboard_metrics_cover_queue_distribution_and_confidence(tmp_path: Path):
    manager = GoldDatasetManager(tmp_path / 'gold.sqlite3')
    manager.create_review(make_review(40, label=ReviewLabel.safe))
    manager.create_review(make_review(41, label=ReviewLabel.phishing))
    dashboard = manager.dashboard()
    assert dashboard.total_samples == 2
    assert dashboard.review_completion == 0.0
    assert dashboard.review_queue['pending'] == 2
    assert dashboard.label_distribution == {'safe': 1, 'phishing': 1}
    assert dashboard.language_distribution == {'en': 2}
    assert dashboard.source_distribution == {'synthetic-source': 2}
    assert dashboard.confidence_distribution['0.75-1.00'] == 2
