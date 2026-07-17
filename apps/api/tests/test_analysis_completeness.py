"""Regression coverage for evidence completeness and HTML-link impersonation."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from app.schemas.analysis import ThreatClassification
from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest
from app.services.analysis_pipeline import AnalysisPipeline


FIXTURE = Path(__file__).parent / 'fixtures' / 'facebook_security_impersonation.eml'


def _run(request: AnalysisPreviewRequest, *, prediction: str = 'legitimate', probability: float = 0.2):
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label=prediction,
            phishing_probability=probability,
            legitimate_probability=1.0 - probability,
        )
        service.model_version = 'regression-model'
        service.decision_threshold = 0.35
        return pipeline.run_request(request)


def test_body_only_safe_is_qualified_and_confidence_capped():
    result = _run(AnalysisPreviewRequest(
        input_mode=AnalysisInputMode.quick_paste,
        subject='Facebook account activity',
        body='We noticed recent activity on your Facebook account. Please review the activity using the security page below. If this was you, no further action is needed. https://www.facebook.com/security',
    ))
    assert result.decision.classification == ThreatClassification.safe
    assert result.decision.confidence <= 0.65
    assert result.analysis_completeness.state == 'body_text_only'
    assert result.analysis_completeness.warning.startswith('Safe based on limited evidence:')


def test_facebook_eml_detects_hidden_destination_even_when_ml_says_legitimate():
    raw_email = FIXTURE.read_text(encoding='utf-8')
    result = _run(AnalysisPreviewRequest(input_mode=AnalysisInputMode.eml_upload, raw_email=raw_email))
    codes = {signal.code for signal in result.rule_analysis.signals}
    assert 'url_trusted_text_unrelated_destination' in codes
    assert 'header_displayname_impersonation' in codes
    assert result.parser.html_links[0].domain_mismatch is True
    assert result.analysis_completeness.state == 'complete_raw_email'
    assert result.engine_agreement == 'disagreement'
    assert result.decision.classification == ThreatClassification.phishing


def test_complete_raw_email_reports_available_evidence():
    result = _run(AnalysisPreviewRequest(input_mode=AnalysisInputMode.raw_email, raw_email=FIXTURE.read_text(encoding='utf-8')))
    completeness = result.analysis_completeness
    assert completeness.has_from_header is True
    assert completeness.has_reply_to is True
    assert completeness.has_return_path is True
    assert completeness.has_html_source is True
    assert completeness.has_real_href_destinations is True
    assert completeness.has_attachment_metadata is True
    assert completeness.warning is None
