from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import FixedWindowLimiter
from app.services.email_parser import parse_email
from app.services.model_manager import ModelManager, ModelRegistryError


client = TestClient(app)


def valid_email() -> str:
    return 'From: sender@example.com\nTo: recipient@example.com\nSubject: Safe\n\nBody'


def test_request_id_is_returned_and_invalid_input_is_replaced():
    response = client.post('/api/v1/parser/preview', json={'raw_email': valid_email()}, headers={'X-Request-ID': 'client-id_1'})
    assert response.status_code == 200
    assert response.headers['X-Request-ID'] == 'client-id_1'

    response = client.get('/api/v1/health', headers={'X-Request-ID': 'bad value'})
    assert response.headers['X-Request-ID'] and len(response.headers['X-Request-ID']) == 36


def test_security_headers_and_cors_are_restrictive():
    response = client.get('/api/v1/health', headers={'Origin': 'http://localhost:3000'})
    assert response.status_code == 200
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers.get('access-control-allow-origin') == 'http://localhost:3000'
    denied = client.get('/api/v1/health', headers={'Origin': 'https://evil.example'})
    assert 'access-control-allow-origin' not in denied.headers


def test_oversized_request_is_rejected_before_parsing():
    response = client.post('/api/v1/parser/preview', content=b'x' * 2_300_000, headers={'Content-Type': 'application/json'})
    assert response.status_code == 413
    assert response.json()['detail']['code'] == 'payload_too_large'


def test_mime_and_control_character_limits_fail_safely():
    with pytest.raises(ValueError, match='control characters'):
        parse_email(valid_email() + '\x00')
    with pytest.raises(ValueError, match='oversized header'):
        parse_email('From: ' + ('x' * 1000) + '@example.com\nTo: recipient@example.com\n\nBody')


def test_model_registry_rejects_artifact_path_escape(tmp_path: Path):
    registry = {
        'schema_version': 1,
        'models': [{
            'model_id': 'safe', 'version': '1', 'artifact_path': '../../outside.joblib',
            'vectorizer_path': 'services/ml/artifacts/vectorizer.joblib',
            'feature_manifest_path': 'services/ml/artifacts/manifest.json',
            'pipeline_hash': '0' * 64, 'vectorizer_hash': '0' * 64,
            'feature_manifest_hash': '0' * 64, 'sha256': '0' * 64,
            'calibration': 'isotonic', 'threshold': 0.5,
            'deployment_candidate': True, 'activated': False,
            'compatible_api_version': '1', 'training_timestamp': 'synthetic',
        }],
    }
    path = tmp_path / 'registry.json'
    path.write_text(json.dumps(registry), encoding='utf-8')
    with pytest.raises(ModelRegistryError, match='outside'):
        ModelManager(path, selected_model_id='safe').discover_models()


def test_rate_limiter_returns_retry_after_without_sleeping():
    limiter = FixedWindowLimiter(60, {'analysis': 1})
    assert limiter.allow('analysis', 'synthetic-client')[0]
    allowed, retry_after = limiter.allow('analysis', 'synthetic-client')
    assert not allowed
    assert retry_after >= 1
