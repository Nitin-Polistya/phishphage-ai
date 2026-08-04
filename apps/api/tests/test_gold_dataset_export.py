from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import dataset_review as dataset_review_api
from app.api.v1 import gold_dataset as gold_dataset_api
from app.core.settings import Settings
from app.main import app
from app.schemas.gemini_review import ReviewLabel
from app.schemas.gold_dataset import GoldDatasetReviewInput, GoldReviewState, LabelQuality
from app.services import private_storage
from app.services.gemini_review_service import GeminiReviewService
from app.services.gemini_review_storage import ReviewStore
from app.services.gold_dataset_manager import ExportVerificationError, GoldDatasetManager


EXPECTED_FILES = {
    'gold_dataset_v1.jsonl',
    'gold_dataset_summary.json',
    'gold_dataset_statistics.md',
    'review_statistics.json',
    'agreement_report.md',
    'quality_metrics.json',
    'label_distribution.csv',
    'gold_dataset_summary.md',
}


def private_path(name: str) -> Path:
    return private_storage.PRIVATE_EVALUATION_ROOT / name


def make_approved(manager: GoldDatasetManager, index: int = 1):
    review = manager.create_review(GoldDatasetReviewInput(
        sample_hash=f'sample-hash-{index}',
        normalized_content_hash=f'normalized-hash-{index}',
        source_dataset='synthetic-source',
        source_sample_id=f'sample-{index}',
        source_identifier=f'source-{index}',
        campaign_identifier=f'campaign-{index}',
        reviewer_name='Alice',
        language='en',
        phishing_label=ReviewLabel.safe,
        label_quality=LabelQuality.high,
        reviewer_confidence=0.95,
        review_notes='Synthetic human review note.',
        requires_second_review=False,
    ))
    manager.transition_state(review.review_id, 'Alice', GoldReviewState.reviewed, 'Human review complete.')
    return manager.transition_state(review.review_id, 'Alice', GoldReviewState.approved, 'Human approved record.')


def test_export_writes_and_verifies_all_expected_files():
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    make_approved(manager)

    exported = manager.export_gold_dataset()
    reports = manager.generate_reports(exported['directory'])
    paths = [*exported['files'], *reports.values()]
    details = manager.verify_export_files(paths)

    assert exported['exported_samples'] == 1
    assert exported['directory_relative'] == 'services/ml/evaluation/private/gold_dataset_reports/'
    assert {item['filename'] for item in details} == EXPECTED_FILES
    assert all(item['status'] == 'written' and item['size_bytes'] >= 0 for item in details)
    assert all(Path(path).is_file() for path in paths)
    assert all(Path(path).resolve().is_relative_to(private_storage.PRIVATE_EVALUATION_ROOT.resolve()) for path in paths)


def test_missing_export_file_fails_verification_without_success():
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    make_approved(manager)
    exported = manager.export_gold_dataset()
    missing = Path(exported['files'][0])
    missing.unlink()

    with pytest.raises(ExportVerificationError, match='gold_dataset_v1.jsonl'):
        manager.verify_export_files([*exported['files']])


def configured_route(monkeypatch, manager: GoldDatasetManager):
    settings = Settings(
        _env_file=None,
        DATASET_REVIEW_ENABLED=True,
        DATASET_REVIEW_LOCAL_ONLY=False,
        DATASET_REVIEW_ADMIN_TOKEN='test-review-token',
        DATASET_REVIEW_STORAGE_PATH='services/ml/evaluation/private/review.sqlite3',
        CORS_ORIGINS='http://localhost:3000',
    )
    store = ReviewStore(private_path('review.sqlite3'))
    monkeypatch.setattr(dataset_review_api, 'get_settings', lambda: settings)
    monkeypatch.setattr(gold_dataset_api, 'review_service', GeminiReviewService(settings, store=store))
    monkeypatch.setattr(gold_dataset_api, '_manager', manager)
    return TestClient(app)


def test_export_route_returns_safe_verified_manifest(monkeypatch):
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    make_approved(manager)
    client = configured_route(monkeypatch, manager)

    response = client.post('/api/v1/dataset-review/gold-dataset/export', headers={'X-Dataset-Review-Token': 'test-review-token'})

    assert response.status_code == 200
    payload = response.json()
    assert payload['exported_count'] == 1
    assert payload['output_location'] == 'services/ml/evaluation/private/gold_dataset_reports/'
    assert payload['all_files_written'] is True
    assert {item['filename'] for item in payload['files']} == EXPECTED_FILES
    assert all(item['status'] == 'written' and item['size_bytes'] >= 0 for item in payload['files'])
    assert str(private_storage.PRIVATE_EVALUATION_ROOT) not in response.text
    assert 'C:\\' not in response.text
    assert '/home/' not in response.text
    assert '@' not in response.text


def test_export_route_distinguishes_no_approved_records_and_invalid_token(monkeypatch):
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    client = configured_route(monkeypatch, manager)

    no_records = client.post('/api/v1/dataset-review/gold-dataset/export', headers={'X-Dataset-Review-Token': 'test-review-token'})
    invalid_token = client.post('/api/v1/dataset-review/gold-dataset/export', headers={'X-Dataset-Review-Token': 'wrong-token'})

    assert no_records.status_code == 409
    assert no_records.json()['detail']['code'] == 'no_approved_records'
    assert invalid_token.status_code == 401
    assert invalid_token.json()['detail']['code'] == 'unauthorized'


def test_export_route_distinguishes_missing_file_failure(monkeypatch):
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    make_approved(manager)

    def fail_verification(_paths):
        raise ExportVerificationError('Export file verification failed for synthetic-missing-file.json.')

    monkeypatch.setattr(manager, 'verify_export_files', fail_verification)
    client = configured_route(monkeypatch, manager)
    response = client.post('/api/v1/dataset-review/gold-dataset/export', headers={'X-Dataset-Review-Token': 'test-review-token'})

    assert response.status_code == 500
    assert response.json()['detail']['code'] == 'export_file_verification_failed'
    assert 'D:\\' not in response.text
    assert '/home/' not in response.text


def test_private_export_rule_is_git_ignored():
    gitignore = Path(__file__).resolve().parents[3] / '.gitignore'
    assert '/services/ml/evaluation/private/*' in gitignore.read_text(encoding='utf-8')
