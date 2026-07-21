from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.model_manager import ModelIntegrityError, ModelManager, ModelManagerError, ModelRegistryError


ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / 'services/ml/models/registry.json'


def registry_payload() -> dict:
    return json.loads(REGISTRY.read_text(encoding='utf-8'))


def write_registry(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / 'registry.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path


def test_default_manager_resolves_from_code_root_even_when_started_in_api(monkeypatch):
    monkeypatch.chdir(ROOT / 'apps/api')
    loaded = ModelManager(selected_model_id='phase-c-logistic-regression-v1').load_deployment_candidate()
    assert loaded.record.artifact_path == ROOT / 'services/ml/artifacts/phase_c_model_development_v1/deployment_candidate/fitted_pipeline.joblib'
    assert loaded.record.threshold == 0.5


def test_matching_registry_hash_is_required_and_accepted():
    loaded = ModelManager(selected_model_id='phase-c-logistic-regression-v1').load_deployment_candidate()
    assert loaded.record.sha256 == loaded.record.pipeline_hash


def test_mismatched_artifact_hash_is_rejected(tmp_path: Path):
    payload = registry_payload()
    payload['models'][0]['sha256'] = '0' * 64
    manager = ModelManager(write_registry(tmp_path, payload), selected_model_id=payload['models'][0]['model_id'])
    with pytest.raises(ModelIntegrityError):
        manager.load_deployment_candidate()


def test_missing_artifact_is_rejected_without_path_in_error(tmp_path: Path):
    payload = registry_payload()
    payload['models'][0]['artifact_path'] = 'services/ml/artifacts/missing/fitted_pipeline.joblib'
    manager = ModelManager(write_registry(tmp_path, payload), selected_model_id=payload['models'][0]['model_id'])
    with pytest.raises(ModelManagerError) as error:
        manager.load_deployment_candidate()
    assert 'missing/fitted_pipeline' not in str(error.value)
    assert str(tmp_path) not in str(error.value)


def test_malformed_registry_and_missing_entry_fail_safely(tmp_path: Path):
    malformed = tmp_path / 'malformed.json'
    malformed.write_text('{not-json', encoding='utf-8')
    with pytest.raises(ModelRegistryError):
        ModelManager(malformed).discover_models()

    payload = registry_payload()
    payload['models'] = []
    manager = ModelManager(write_registry(tmp_path, payload), selected_model_id='phase-c-logistic-regression-v1')
    with pytest.raises(ModelManagerError):
        manager.load_deployment_candidate()


def test_health_exposes_safe_readiness_state_without_filesystem_paths():
    health = ModelManager(selected_model_id='phase-c-logistic-regression-v1').health()
    assert health['registry_loaded'] is True
    assert health['artifact_found'] is True
    assert health['hash_verified'] is True
    assert health['inference_ready'] is True
    assert 'path' not in json.dumps(health).lower()
