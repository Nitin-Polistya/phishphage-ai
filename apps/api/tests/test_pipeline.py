"""Integration tests for the Analysis Pipeline."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.services.analysis_pipeline import AnalysisPipeline, MLUnavailableError
from app.schemas.analysis import ThreatClassification

# Mock raw emails
SAFE_EMAIL = "From: alice@example.com\nSubject: Hello\n\nJust saying hi!"
PHISHING_EMAIL = "From: scam@bad.com\nSubject: URGENT: Verify Account\n\nPlease login at http://evil.com/login to avoid account closure!"
INVALID_EMAIL = "   "

def test_pipeline_execution_success():
    """Test that the pipeline runs from end to end successfully."""
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        # Setup mock ML result
        mock_service = MockML.return_value
        mock_service.predict.return_value = MagicMock(
            predicted_label="legitimate",
            phishing_probability=0.1,
            legitimate_probability=0.9,
            model_version="test-v1"
        )
        mock_service.model_version = "test-v1"

        result = pipeline.run(SAFE_EMAIL)
        
        assert result.parser.subject == "Hello"
        assert result.ml_analysis.status == "available"
        assert result.ml_analysis.prediction == "legitimate"
        assert result.decision.classification in {ThreatClassification.safe, ThreatClassification.suspicious}

def test_pipeline_obvious_phishing():
    """Test that obvious phishing is detected when both agree."""
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        mock_service = MockML.return_value
        mock_service.predict.return_value = MagicMock(
            predicted_label="phishing",
            phishing_probability=0.98,
            legitimate_probability=0.02,
            model_version="test-v1"
        )
        mock_service.model_version = "test-v1"

        result = pipeline.run(PHISHING_EMAIL)
        
        assert result.decision.classification == ThreatClassification.phishing
        assert result.decision.risk_score >= 70

def test_pipeline_disagreement_conservative():
    """Test that disagreement leads to 'suspicious' classification (conservative)."""
    pipeline = AnalysisPipeline(ml_required=False)
    # Use a moderately suspicious email instead of the obvious one to avoid "overwhelming" rule signal
    MODERATE_EMAIL = "From: user@example.com\nSubject: Account Update\n\nPlease review your account details."
    
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        # ML says phishing, but Rules say safe/suspicious
        mock_service = MockML.return_value
        mock_service.predict.return_value = MagicMock(
            predicted_label="phishing",
            phishing_probability=0.6,
            legitimate_probability=0.4,
            model_version="test-v1"
        )
        mock_service.model_version = "test-v1"

        result = pipeline.run(MODERATE_EMAIL)
        
        # Rules (safe/low) vs ML (phishing/moderate) -> suspicious
        assert result.decision.classification == ThreatClassification.suspicious

def test_pipeline_missing_model_falls_back_to_rules(tmp_path):
    pipeline = AnalysisPipeline(model_path=tmp_path / 'missing.joblib', ml_required=False)

    result = pipeline.run(SAFE_EMAIL)

    assert result.ml_analysis.status == 'unavailable'
    assert result.ml_analysis.prediction is None
    assert result.ml_analysis.phishing_probability is None
    assert result.ml_analysis.legitimate_probability is None
    assert result.ml_analysis.model_version is None
    assert result.decision.classification == result.rule_analysis.classification
    assert result.decision.risk_score == result.rule_analysis.risk_score
    assert result.decision.confidence == result.rule_analysis.confidence


def test_pipeline_missing_model_required_raises_safe_error(tmp_path):
    pipeline = AnalysisPipeline(model_path=tmp_path / 'private' / 'missing.joblib', ml_required=True)

    with pytest.raises(MLUnavailableError) as excinfo:
        pipeline.run(SAFE_EMAIL)

    assert str(tmp_path) not in str(excinfo.value)

def test_pipeline_invalid_email():
    """Test that invalid email content is handled by the parser."""
    with pytest.raises(ValueError) as excinfo:
        AnalysisPipeline(ml_required=False).run(INVALID_EMAIL)
    assert "Email content cannot be empty" in str(excinfo.value)

def test_pipeline_ml_inference_failure_falls_back_to_rules():
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as MockML:
        mock_service = MockML.return_value
        mock_service.predict.side_effect = Exception("Inference crashed")
        
        result = pipeline.run(SAFE_EMAIL)
        assert result.ml_analysis.status == 'unavailable'
        assert result.decision.risk_score == result.rule_analysis.risk_score
