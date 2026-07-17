from fastapi.testclient import TestClient
from app.main import app
from unittest.mock import patch, MagicMock
from typing import Any

import pytest

from app.services.analysis_pipeline import pipeline

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_pipeline_state():
    original_required = pipeline.ml_required
    original_path = pipeline.model_path
    pipeline._ml_service = None  # type: ignore[protected-access]
    yield
    pipeline.ml_required = original_required
    pipeline.model_path = original_path
    pipeline._ml_service = None  # type: ignore[protected-access]


def test_preview_valid_legit():
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        mock_service = MockML.return_value
        mock_service.predict.return_value = MagicMock(
            predicted_label="legitimate",
            phishing_probability=0.1,
            legitimate_probability=0.9,
            model_version="test-v1"
        )
        mock_service.model_version = "test-v1"

        raw = 'From: alice@example.com\nSubject: Hello\n\nThis is a normal message.'
        resp = client.post('/api/v1/analysis/preview', json={'raw_email': raw})
        assert resp.status_code == 200
        data: Any = resp.json()
        assert 'decision' in data
        assert 'risk_score' in data['decision']
        assert data['ml_analysis']['status'] == 'available'


def test_preview_suspicious():
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        mock_service = MockML.return_value
        mock_service.predict.return_value = MagicMock(
            predicted_label="phishing",
            phishing_probability=0.9,
            legitimate_probability=0.1,
            model_version="test-v1"
        )
        mock_service.model_version = "test-v1"

        raw = 'From: attacker@bad.com\nSubject: URGENT: Verify your password\n\nClick here: http://bit.ly/evil\n'
        resp = client.post('/api/v1/analysis/preview', json={'raw_email': raw})
        assert resp.status_code == 200
        data: Any = resp.json()
        assert data['decision']['risk_score'] >= 30


def test_preview_missing_raw_email_returns_422():
    resp = client.post('/api/v1/analysis/preview', json={})
    assert resp.status_code == 422


def test_preview_empty_input_returns_400():
    resp = client.post('/api/v1/analysis/preview', json={'raw_email': ''})
    assert resp.status_code == 400


def test_preview_without_model_returns_rule_only_response(tmp_path):
    pipeline.model_path = tmp_path / 'missing.joblib'
    pipeline.ml_required = False

    resp = client.post('/api/v1/analysis/preview', json={'raw_email': 'From: alice@example.com\nSubject: Hello\n\nNormal message.'})

    assert resp.status_code == 200
    data = resp.json()
    assert data['parser']['subject'] == 'Hello'
    assert data['ml_analysis'] == {
        'status': 'unavailable',
        'prediction': None,
        'phishing_probability': None,
        'legitimate_probability': None,
        'model_version': None,
        'reason': 'Machine-learning analysis is unavailable.',
        'decision_threshold': None,
    }
    assert data['decision']['classification'] == data['rule_analysis']['classification']
    assert data['decision']['risk_score'] == data['rule_analysis']['risk_score']
    assert data['decision']['confidence'] == min(data['rule_analysis']['confidence'], 0.65)
    assert data['analysis_completeness']['limited_evidence'] is True
    assert 0 <= data['decision']['risk_score'] <= 100
    assert 0 <= data['decision']['confidence'] <= 1


def test_preview_without_required_model_returns_safe_503(tmp_path):
    pipeline.model_path = tmp_path / 'secret' / 'missing.joblib'
    pipeline.ml_required = True

    resp = client.post('/api/v1/analysis/preview', json={'raw_email': 'From: alice@example.com\nSubject: Hello\n\nNormal message.'})

    assert resp.status_code == 503
    assert resp.json() == {'detail': 'Machine-learning analysis is temporarily unavailable.'}
    assert str(tmp_path) not in resp.text
