from __future__ import annotations

import json
import logging
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app, _startup_diagnostics, settings
from app.core import firebase as firebase_module
from app.core.runtime_metrics import runtime_metrics
from app.services.analysis_pipeline import pipeline


client = TestClient(app)
SYNTHETIC_EMAIL = 'From: sender@example.com\nSubject: synthetic verification\n\nSynthetic body only.'


def test_request_id_is_correlated_and_request_log_is_structured(caplog):
    caplog.set_level('INFO')
    response = client.get('/api/v1/health', headers={'X-Request-ID': 'observability-test-1', 'User-Agent': 'synthetic-agent'})
    assert response.status_code == 200
    assert response.headers['X-Request-ID'] == 'observability-test-1'
    records = [record for record in caplog.records if record.name == 'phishshield.request']
    assert records
    event = getattr(records[-1], 'structured')
    assert event['method'] == 'GET'
    assert event['path'] == '/api/v1/health'
    assert event['response_status'] == 200
    assert event['success'] is True
    assert len(event['client_ip']) == 16
    assert event['user_agent'] == 'synthetic-agent'
    assert SYNTHETIC_EMAIL not in caplog.text


def test_health_contains_safe_runtime_and_model_metadata():
    payload = client.get('/api/v1/health').json()
    assert payload['application_version'] == '1.0.0-rc1'
    assert payload['environment']
    assert payload['uptime_seconds'] >= 0
    assert payload['request_counts']['total'] >= 0
    assert payload['analysis_counts']['total'] >= 0
    assert payload['registry_version'] == 'phase_d_registry_v1'
    assert payload['artifact_hash']
    assert payload['firebase_enabled'] is False
    assert payload['rate_limiter_enabled'] is True
    assert 'filesystem' not in json.dumps(payload).lower()


def test_ready_and_metrics_are_json_and_privacy_safe():
    ready = client.get('/ready')
    assert ready.status_code == 200
    assert ready.json()['status'] == 'ready'

    client.post('/api/v1/analyze', json={'raw_email': SYNTHETIC_EMAIL})
    response = client.get('/metrics')
    assert response.status_code == 200
    payload = response.json()
    assert payload['total_requests'] >= 1
    assert payload['total_analysis_requests'] >= 1
    assert payload['model_inference_calls'] >= 1
    assert payload['average_request_latency_ms'] >= 0
    assert payload['average_inference_latency_ms'] >= 0
    assert payload['model']['model_id'] == 'phase-c-logistic-regression-v1'
    assert SYNTHETIC_EMAIL not in json.dumps(payload)
    assert 'private_key' not in json.dumps(payload).lower()


def test_startup_diagnostics_are_safe(caplog):
    caplog.set_level('INFO')
    _startup_diagnostics()
    records = [record for record in caplog.records if record.name == 'app.main' and record.message == 'startup.diagnostics']
    assert records
    serialized = json.dumps(getattr(records[-1], 'structured'))
    assert 'artifact_hash' in serialized
    assert 'FIREBASE_PRIVATE_KEY' not in serialized
    assert SYNTHETIC_EMAIL not in serialized


def test_startup_state_is_explicit_and_consistent_across_health_ready_metrics():
    metrics = client.get('/metrics').json()
    startup = metrics['startup_diagnostics']
    health = client.get('/api/v1/health').json()
    required = {
        'settings_initialization_ms', 'registry_load_ms', 'artifact_hash_ms',
        'model_load_ms', 'model_warmup_ms', 'total_startup_ms',
        'ml_required', 'model_configured', 'model_available', 'inference_ready',
        'fallback_allowed', 'fallback_active', 'model_id', 'model_version',
        'registry_version', 'artifact_hash_verified',
    }
    assert required.issubset(startup)
    assert startup['ml_enabled'] is startup['inference_ready']
    assert startup['model_available'] is True
    assert startup['inference_ready'] is True
    assert startup['artifact_hash_verified'] is True
    assert startup['model_available'] == health['model_available']
    assert startup['inference_ready'] == health['inference_ready']
    assert all(isinstance(startup[key], (int, float)) and startup[key] >= 0 for key in {
        'settings_initialization_ms', 'registry_load_ms', 'artifact_hash_ms',
        'model_load_ms', 'model_warmup_ms', 'total_startup_ms',
    })
    assert 'path' not in json.dumps(startup).lower()


def test_options_are_separate_and_post_analysis_counts_once():
    before = runtime_metrics.snapshot()
    valid_preflight = client.options(
        '/api/v1/analyze',
        headers={
            'Origin': 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type',
        },
    )
    assert valid_preflight.status_code == 200
    assert valid_preflight.headers.get('access-control-allow-origin') == 'http://localhost:3000'
    after_preflight = runtime_metrics.snapshot()
    assert after_preflight['options_requests'] == before['options_requests'] + 1
    assert after_preflight['total_analysis_requests'] == before['total_analysis_requests']

    rejected_preflight = client.options(
        '/api/v1/analyze',
        headers={
            'Origin': 'https://untrusted.example',
            'Access-Control-Request-Method': 'POST',
        },
    )
    assert rejected_preflight.status_code == 400
    after_rejected = runtime_metrics.snapshot()
    assert after_rejected['options_requests'] == after_preflight['options_requests'] + 1
    assert after_rejected['failed_options_requests'] == after_preflight['failed_options_requests'] + 1
    assert after_rejected['total_analysis_requests'] == before['total_analysis_requests']

    response = client.post('/api/v1/analyze', json={'raw_email': SYNTHETIC_EMAIL})
    assert response.status_code == 200
    after_post = runtime_metrics.snapshot()
    assert after_post['total_analysis_requests'] == before['total_analysis_requests'] + 1
    assert after_post['model_inference_calls'] == before['model_inference_calls'] + 1


def test_first_analysis_is_warmed_before_request_handling():
    started = time.perf_counter()
    response = client.post('/api/v1/analyze', json={'raw_email': SYNTHETIC_EMAIL})
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert response.status_code == 200
    assert elapsed_ms < 1000


def test_unified_analysis_stage_timing_is_safe(caplog):
    caplog.set_level(logging.DEBUG, logger='app.services.analysis_pipeline')
    response = client.post('/api/v1/analysis/preview', json={'raw_email': SYNTHETIC_EMAIL})
    assert response.status_code == 200
    records = [record for record in caplog.records if record.message == 'analysis.timing']
    assert records
    timing = getattr(records[-1], 'structured')
    assert {'parser_ms', 'rules_ms', 'inference_ms', 'total_ms'}.issubset(timing)
    assert all(timing[key] >= 0 for key in {'parser_ms', 'rules_ms', 'inference_ms', 'total_ms'})
    assert SYNTHETIC_EMAIL not in json.dumps(timing)


def test_firebase_configuration_states_are_structured_and_safe(monkeypatch, caplog):
    class FakeSettings:
        firebase_project_id = None
        firebase_client_email = None
        firebase_private_key = None

    monkeypatch.setattr(firebase_module, 'get_settings', lambda: FakeSettings())
    caplog.set_level(logging.INFO, logger='app.core.firebase')
    firebase_module._initialize_firebase()
    disabled = [record for record in caplog.records if record.message == 'firebase.disabled']
    assert disabled
    assert getattr(disabled[-1], 'structured')['reason_code'] == 'not_configured'
    assert disabled[-1].levelno == logging.INFO

    class PartialSettings(FakeSettings):
        firebase_project_id = 'project-only'

    monkeypatch.setattr(firebase_module, 'get_settings', lambda: PartialSettings())
    firebase_module._initialize_firebase()
    partial = [record for record in caplog.records if record.message == 'firebase.partial_configuration']
    assert partial
    assert partial[-1].levelno == logging.WARNING
    serialized = json.dumps(getattr(partial[-1], 'structured'))
    assert 'project-only' not in serialized
    assert 'private_key' not in serialized.lower()

    class CompleteSettings(PartialSettings):
        firebase_client_email = 'client@example.invalid'
        firebase_private_key = 'not-a-real-key'

    def fail_certificate(_value):
        raise RuntimeError('credential construction failed')

    monkeypatch.setattr(firebase_module, 'get_settings', lambda: CompleteSettings())
    monkeypatch.setattr(firebase_module.credentials, 'Certificate', fail_certificate)
    firebase_module._initialize_firebase()
    failed = [record for record in caplog.records if record.message == 'firebase.initialization_failed']
    assert failed
    failure_payload = getattr(failed[-1], 'structured')
    assert failure_payload['reason_code'] == 'initialization_error'
    assert 'not-a-real-key' not in json.dumps(failure_payload)


def test_required_startup_failure_is_not_served_from_partial_model_state(monkeypatch):
    monkeypatch.setattr(settings, 'ml_required', True)

    def fail_prepare(_warmup_text=None):
        raise RuntimeError('synthetic required startup failure')

    monkeypatch.setattr(pipeline, 'prepare', fail_prepare)
    with pytest.raises(RuntimeError, match='Required inference initialization failed'):
        _startup_diagnostics()
    failed = runtime_metrics.startup_diagnostics()
    assert failed['startup_complete'] is False
    assert failed['inference_ready'] is False
    assert failed['model_available'] is False
    assert pipeline.inference_ready is False

    monkeypatch.undo()
    restored = _startup_diagnostics()
    assert restored['startup_complete'] is True
    assert restored['inference_ready'] is True
