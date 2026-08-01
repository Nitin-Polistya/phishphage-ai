from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import dataset_review as dataset_review_api
from app.core.settings import Settings
from app.main import app
from app.schemas.gemini_review import SanitizedReviewInput
from app.services import gemini_review_storage, gold_dataset_manager, private_storage
from app.services.gemini_review_service import GeminiReviewService
from app.services.gemini_review_storage import ReviewStore
from app.services.gold_dataset_manager import GoldDatasetError, GoldDatasetManager


def private_path(name: str) -> Path:
    return private_storage.PRIVATE_EVALUATION_ROOT / name


def test_valid_private_storage_path_is_accepted_by_both_stores():
    gold = GoldDatasetManager(private_path('gold.sqlite3'))
    review = ReviewStore(private_path('review.sqlite3'))

    assert gold.path == private_path('gold.sqlite3').resolve()
    assert review.path == private_path('review.sqlite3').resolve()


def test_storage_path_outside_private_root_is_rejected():
    outside = private_storage.PRIVATE_EVALUATION_ROOT.parent / 'outside.sqlite3'

    with pytest.raises(GoldDatasetError, match='private evaluation directory'):
        GoldDatasetManager(outside)
    with pytest.raises(ValueError, match='private evaluation directory'):
        ReviewStore(outside)


def test_storage_path_traversal_is_rejected():
    traversal = private_storage.PRIVATE_EVALUATION_ROOT / '..' / 'traversal.sqlite3'

    with pytest.raises(GoldDatasetError, match='private evaluation directory'):
        GoldDatasetManager(traversal)
    with pytest.raises(ValueError, match='private evaluation directory'):
        ReviewStore(traversal)


def test_relative_storage_path_is_independent_of_working_directory(monkeypatch, tmp_path: Path):
    configured_path = 'services/ml/evaluation/private/cwd-independent.sqlite3'
    settings = type('StorageSettings', (), {'dataset_review_storage_path': configured_path})()
    other_working_directory = tmp_path / 'unrelated-working-directory'
    other_working_directory.mkdir()
    monkeypatch.chdir(other_working_directory)
    monkeypatch.setattr(gold_dataset_manager, 'get_settings', lambda: settings)
    monkeypatch.setattr(gemini_review_storage, 'get_settings', lambda: settings)

    gold = GoldDatasetManager()
    review = ReviewStore()

    expected = private_path('cwd-independent.sqlite3').resolve()
    assert gold.path == expected
    assert review.path == expected


def test_default_exports_and_reports_stay_under_private_root():
    manager = GoldDatasetManager(private_path('gold.sqlite3'))
    exported = manager.export_gold_dataset()
    reports = manager.generate_reports()

    paths = [Path(exported['directory']), *[Path(path) for path in exported['files']], *reports.values()]
    assert all(path.is_relative_to(private_storage.PRIVATE_EVALUATION_ROOT) for path in paths)


def test_preview_persists_locally_without_absolute_path_leakage(monkeypatch):
    settings = Settings(
        _env_file=None,
        DATASET_REVIEW_ENABLED=True,
        DATASET_REVIEW_LOCAL_ONLY=False,
        DATASET_REVIEW_ADMIN_TOKEN='test-review-token',
        GEMINI_MODEL='synthetic-model',
        DATASET_REVIEW_STORAGE_PATH='services/ml/evaluation/private/preview.sqlite3',
        CORS_ORIGINS='http://localhost:3000',
    )
    monkeypatch.setattr(dataset_review_api, 'get_settings', lambda: settings)
    monkeypatch.setattr(gemini_review_storage, 'get_settings', lambda: settings)
    store = ReviewStore()
    monkeypatch.setattr(
        dataset_review_api,
        'review_service',
        GeminiReviewService(settings, store=store),
    )

    evidence = SanitizedReviewInput(
        sample_id='storage-regression-001',
        subject='Synthetic account notice',
        display_name='Synthetic Sender',
        sender_domain='mail.example.com',
        reply_to_domain='reply.example.org',
        authentication_summary=['spf=pass'],
        body_excerpt='Synthetic evidence only. Visit https://example.com for context.',
        url_domains=['https://example.com/path'],
        parser_evidence=['url_count:1'],
    )
    response = TestClient(app).post(
        '/api/v1/dataset-review/preview',
        json=evidence.model_dump(mode='json'),
        headers={'X-Dataset-Review-Token': 'test-review-token'},
    )

    assert response.status_code == 200
    assert str(private_storage.PRIVATE_EVALUATION_ROOT) not in response.text
    with sqlite3.connect(store.path) as connection:
        row = connection.execute('SELECT sample_id FROM review_samples WHERE sample_id=?', (evidence.sample_id,)).fetchone()
    assert row == (evidence.sample_id,)


def test_preview_suggest_review_flow_uses_strict_provider_output(monkeypatch):
    settings = Settings(
        _env_file=None,
        DATASET_REVIEW_ENABLED=True,
        DATASET_REVIEW_LOCAL_ONLY=False,
        DATASET_REVIEW_ADMIN_TOKEN='test-review-token',
        GEMINI_REVIEW_ENABLED=True,
        GEMINI_API_KEY='synthetic-provider-key',
        GEMINI_MODEL='synthetic-model',
        DATASET_REVIEW_STORAGE_PATH='services/ml/evaluation/private/route-flow.sqlite3',
        CORS_ORIGINS='http://localhost:3000',
    )

    class Response:
        text = json.dumps({
            'suggested_label': 'suspicious',
            'confidence': 0.7,
            'summary': 'Synthetic advisory output for route validation.',
            'evidence': [],
            'contrary_evidence': [],
            'sender_domain_assessment': 'Synthetic sender domain assessment.',
            'authentication_assessment': 'Synthetic authentication assessment.',
            'missing_evidence': [],
            'ambiguity_notes': [],
            'reviewer_questions': [],
            'safety_notes': ['Human review remains authoritative.'],
        })

    class Models:
        def generate_content(self, **_kwargs):
            return Response()

    class Client:
        models = Models()

    monkeypatch.setattr(dataset_review_api, 'get_settings', lambda: settings)
    monkeypatch.setattr(gemini_review_storage, 'get_settings', lambda: settings)
    service = GeminiReviewService(settings, store=ReviewStore(), client_factory=lambda _settings: Client())
    monkeypatch.setattr(dataset_review_api, 'review_service', service)
    client = TestClient(app)
    headers = {
        'X-Dataset-Review-Token': 'test-review-token',
        'X-Dataset-Review-Session': 'synthetic-route-session',
    }
    evidence = {
        'sample_id': 'route-flow-001',
        'subject': 'Synthetic account notice',
        'display_name': 'Synthetic Sender',
        'sender_domain': 'mail.example.com',
        'reply_to_domain': 'reply.example.org',
        'authentication_summary': ['spf=pass'],
        'body_excerpt': 'Synthetic evidence only.',
        'url_domains': [],
        'parser_evidence': [],
    }

    preview = client.post('/api/v1/dataset-review/preview', json=evidence, headers=headers)
    assert preview.status_code == 200
    suggest = client.post(
        '/api/v1/dataset-review/suggest',
        json={
            'payload': preview.json()['payload'],
            'consent': True,
            'review_mode': 'independent',
            'reviewer_alias': 'synthetic-reviewer',
            'preliminary_label': 'suspicious',
            'preliminary_notes': 'Synthetic preliminary review.',
        },
        headers=headers,
    )
    assert suggest.status_code == 200
    assert suggest.json()['advisory_only'] is True
    assert suggest.json()['ground_truth_changed'] is False

    review = client.get('/api/v1/dataset-review/reviews/route-flow-001', headers=headers)
    assert review.status_code == 200
    assert review.json()['status'] == 'gemini_suggested'
