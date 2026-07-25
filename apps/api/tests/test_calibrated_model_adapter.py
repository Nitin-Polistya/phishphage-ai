from __future__ import annotations

import json

import pytest

from app.services.analysis_pipeline import AnalysisPipeline
from app.services.model_manager import ModelManager
from phishshield_ml.inference import LocalInferenceService, ModelAdapter, ModelAdapterError


RAW = "From: sender@example.com\nSubject: Verify account\n\nPlease verify your password immediately."


def test_approved_calibrated_wrapper_is_supported_without_top_level_named_steps():
    loaded = ModelManager(selected_model_id="phase-c-logistic-regression-v1").load_deployment_candidate()
    assert type(loaded.predictor).__name__ == "CalibratedModel"
    assert not hasattr(loaded.predictor, "named_steps")
    service = LocalInferenceService.from_verified_model(loaded)
    result = service.predict("Verify account\nPlease verify your password immediately.")
    direct = loaded.predictor.predict_proba(["Verify account Please verify your password immediately."])[0][1]
    assert result.phishing_probability == pytest.approx(float(direct), abs=1e-12)
    assert result.model_version == loaded.record.version
    assert service.decision_threshold == loaded.record.threshold == 0.5


def test_analysis_pipeline_does_not_fallback_for_valid_calibrated_wrapper():
    response = AnalysisPipeline(ml_required=True).run(RAW)
    assert response.ml_analysis.status.value == "available"
    assert response.ml_analysis.model_version == "1.0.0"
    assert response.ml_phishing_probability is not None
    assert response.ml_threshold == 0.5


def test_unsupported_shape_and_class_order_fail_safely():
    with pytest.raises(ModelAdapterError):
        ModelAdapter(object(), {"legitimate": 0, "phishing": 1})
    loaded = ModelManager(selected_model_id="phase-c-logistic-regression-v1").load_deployment_candidate()
    with pytest.raises(ModelAdapterError):
        ModelAdapter(loaded.predictor, {"legitimate": 1, "phishing": 0})


def test_health_reports_calibrated_inference_ready_without_paths():
    health = ModelManager(selected_model_id="phase-c-logistic-regression-v1").health()
    assert health["inference_ready"] is True
    assert health["hash_verified"] is True
    assert "path" not in json.dumps(health).lower()
