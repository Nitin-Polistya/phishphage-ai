from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.model_manager import ModelIntegrityError, ModelManager, ModelVersionError
from app.services.inference_service import inference_service


client = TestClient(app)
RAW = "From: sender@example.com\nSubject: Verify account\n\nPlease verify your password immediately."


def test_prediction_endpoint_returns_privacy_safe_contract():
    response = client.post('/api/v1/analyze', json={'raw_email': RAW})
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        'model_id', 'model_version', 'prediction', 'probability', 'risk_score', 'confidence',
        'threshold_used', 'feature_families', 'signals', 'recommendations', 'processing_time_ms',
    }
    assert payload['model_id'] == 'phase-c-logistic-regression-v1'
    assert payload['model_version'] == '1.0.0'
    assert payload['threshold_used'] == 0.5
    assert payload['prediction'] in {'phishing', 'legitimate'}
    assert 'coefficients' not in json.dumps(payload).lower()


def test_health_reports_shared_loaded_candidate():
    client.post('/api/v1/analyze', json={'raw_email': RAW})
    response = client.get('/api/v1/health')
    assert response.status_code == 200
    payload = response.json()
    assert payload['loaded_model'] == 'phase-c-logistic-regression-v1'
    assert payload['model_version'] == '1.0.0'
    assert payload['calibration'] == 'isotonic'
    assert payload['deployment_candidate'] is True
    assert payload['activated'] is False
    assert payload['pipeline_sha']


def test_invalid_email_is_structured_error():
    response = client.post('/api/v1/analyze', json={'raw_email': ''})
    assert response.status_code == 422  # Pydantic input validation
    response = client.post('/api/v1/analyze', json={'raw_email': '   '})
    assert response.status_code in {400, 422}
    if response.status_code == 400:
        assert response.json()['detail']['code'] == 'invalid_email'


def test_registry_hash_mismatch_is_rejected(tmp_path: Path):
    source = Path('services/ml/models/registry.json')
    payload = json.loads(source.read_text(encoding='utf-8'))
    payload['models'][0]['sha256'] = '0' * 64
    registry = tmp_path / 'registry.json'
    registry.write_text(json.dumps(payload), encoding='utf-8')
    manager = ModelManager(registry)
    with pytest.raises(ModelIntegrityError):
        manager.load_deployment_candidate()


def test_incompatible_registry_version_is_rejected(tmp_path: Path):
    payload = json.loads(Path('services/ml/models/registry.json').read_text(encoding='utf-8'))
    payload['models'][0]['compatible_api_version'] = '99'
    registry = tmp_path / 'registry.json'
    registry.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ModelVersionError):
        ModelManager(registry).load_deployment_candidate()


def test_concurrent_predictions_are_consistent():
    inference_service.predict_email(__import__('app.services.email_parser', fromlist=['parse_email']).parse_email(RAW))
    parsed = __import__('app.services.email_parser', fromlist=['parse_email']).parse_email(RAW)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(inference_service.predict_email, [parsed] * 12))
    assert {result.prediction for result in results} == {'phishing'}
    assert len({result.model_id for result in results}) == 1
    assert max(result.processing_time_ms for result in results) < 5000
