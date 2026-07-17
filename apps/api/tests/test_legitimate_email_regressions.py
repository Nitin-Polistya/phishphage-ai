"""Accuracy regression tests for authenticated legitimate HTML email."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.header_analyzer import analyze_headers, evaluate_authentication
from app.analyzers.url_analyzer import analyze_urls
from app.schemas.analysis import AnalysisResult, ThreatClassification, ThreatSignal
from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest, EmailUrlEvidence, UrlSourceType
from app.services.analysis_pipeline import AnalysisPipeline
from app.services.decision_engine import fuse_analysis_results
from app.services.domain_utils import domains_align, registrable_domain
from app.services.email_parser import parse_email


FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'legitimate_regression'
FIXTURE_PROBABILITIES = {
    'cline_hubspot_newsletter.eml': 0.359566,
    'github_education_approval.eml': 0.502895,
    'gmail_inbox_welcome_missing_auth.eml': 0.531410,
    'openai_mandrill_subscription.eml': 0.482337,
    'unstop_moengage_promotion.eml': 0.344276,
}


def _run_fixture(filename: str):
    probability = FIXTURE_PROBABILITIES[filename]
    prediction = 'phishing' if probability >= 0.5 else 'legitimate'
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label=prediction,
            phishing_probability=probability,
            legitimate_probability=1.0 - probability,
        )
        service.model_version = 'ml-english-template-robust-v3.0.0'
        service.decision_threshold = 0.5
        return pipeline.run_request(AnalysisPreviewRequest(
            input_mode=AnalysisInputMode.raw_email,
            raw_email=(FIXTURE_DIR / filename).read_text(encoding='utf-8'),
        ))


@pytest.mark.parametrize('filename', sorted(FIXTURE_PROBABILITIES))
def test_sanitized_legitimate_fixture_is_not_phishing(filename):
    result = _run_fixture(filename)
    assert result.rule_analysis.classification == ThreatClassification.safe
    assert result.decision.classification == ThreatClassification.safe
    assert result.rule_analysis.engine_version == 'rules-v3.1.0'
    assert result.ml_analysis.model_version == 'ml-english-template-robust-v3.0.0'
    if 'missing_auth' in filename:
        assert result.positive_authentication_evidence == []
        assert result.authentication_evidence_status == 'unavailable'
        assert result.engine_agreement == 'disagreement'
        assert result.analysis_completeness.limited_evidence is True
        assert result.analysis_completeness.warning.startswith('Safe based on limited authentication evidence:')
        assert result.decision.confidence <= 0.60
        assert result.decision.limited_authentication_evidence is True
        assert any('official service' in recommendation for recommendation in result.recommendations)
    else:
        assert result.positive_authentication_evidence
    assert result.rule_raw_score == result.rule_adjusted_score
    assert result.rule_adjusted_score <= (5 if 'missing_auth' in filename else 4)
    assert result.fusion_reason
    assert result.analysis_freshness == 'current'
    assert result.stale_reason is None


def test_parser_records_url_source_semantics_without_fetching():
    parsed = parse_email((FIXTURE_DIR / 'cline_hubspot_newsletter.eml').read_text(encoding='utf-8'))
    sources = {item.source_type for item in parsed.url_evidence}
    assert {
        UrlSourceType.anchor_href,
        UrlSourceType.plain_text,
        UrlSourceType.image_src,
        UrlSourceType.tracking_pixel,
        UrlSourceType.css_resource,
        UrlSourceType.document_metadata,
        UrlSourceType.namespace_or_dtd,
    } <= sources
    assert all(item.user_actionable == (item.source_type in {
        UrlSourceType.anchor_href, UrlSourceType.plain_text, UrlSourceType.form_action,
    }) for item in parsed.url_evidence)


def test_form_action_is_actionable_but_assets_and_pixels_are_not():
    raw = """From: sender@example.com
To: recipient@example.net
Subject: HTML semantics
Content-Type: text/html; charset=utf-8

<html><body><form action="http://evil.example/login"><button>Continue</button></form>
<img src="http://cdn.example/accounts/banner.png"><img width="1" height="1" src="http://track.example/open.gif">
</body></html>"""
    parsed = parse_email(raw)
    by_source = {item.source_type: item for item in parsed.url_evidence}
    assert by_source[UrlSourceType.form_action].user_actionable is True
    assert by_source[UrlSourceType.image_src].user_actionable is False
    assert by_source[UrlSourceType.tracking_pixel].user_actionable is False
    codes = {signal.code for signal in analyze_urls(
        parsed.extracted_urls, sender_domain='example.com', url_evidence=parsed.url_evidence,
    )}
    assert 'url_insecure_scheme' in codes
    assert 'url_suspicious_keyword' in codes


def test_non_actionable_http_assets_do_not_create_transport_or_keyword_findings():
    evidence = [
        EmailUrlEvidence(url='http://cdn.example/accounts/banner.png', source_type='image_src'),
        EmailUrlEvidence(url='http://track.example/open.gif', source_type='tracking_pixel'),
        EmailUrlEvidence(url='http://schema.example/account', source_type='namespace_or_dtd'),
    ]
    assert analyze_urls([item.url for item in evidence], sender_domain='example.com', url_evidence=evidence) == []


@pytest.mark.parametrize(('hostname', 'expected'), [
    ('mail.example.co.uk', 'example.co.uk'),
    ('tm.openai.com', 'openai.com'),
    ('delivery.unstop.news', 'unstop.news'),
    ('service.github.io', 'service.github.io'),
])
def test_registrable_domain_uses_public_suffix_list(hostname, expected):
    assert registrable_domain(hostname) == expected


def test_domain_alignment_rejects_deceptive_and_lookalike_domains():
    assert domains_align('tm.openai.com', 'openai.com')
    assert domains_align('delivery.unstop.news', 'unstop.news')
    assert not domains_align('openai.com.attacker.example', 'openai.com')
    assert not domains_align('paypa1.com', 'paypal.com')


def test_authentication_states_and_authenticated_esp_suppression():
    headers = {
        'Reply-To': 'support@openai.com',
        'Return-Path': '<bounce@mandrill.example>',
        'Authentication-Results': (
            'mx; spf=pass smtp.mailfrom=mandrill.example; '
            'dkim=pass header.d=openai.com; dmarc=pass header.from=tm.openai.com'
        ),
    }
    assessment = evaluate_authentication(headers, 'noreply@tm.openai.com')
    assert assessment.trusted_sender is True
    assert [item.state.value for item in assessment.evidence] == ['pass', 'pass', 'pass']
    assert not analyze_headers(headers, 'noreply@tm.openai.com', 'OpenAI', None, '<id@tm.openai.com>')

    missing = evaluate_authentication({}, 'sender@example.com')
    assert {item.state.value for item in missing.evidence} == {'missing'}
    assert missing.trusted_sender is False


def test_positive_authentication_does_not_override_strong_malicious_evidence():
    rule = AnalysisResult(
        classification='phishing', risk_score=94, confidence=0.92, engine_version='rules-v3.1.0',
        signals=[ThreatSignal(
            code='content_credential_request', category='content', severity='high',
            title='Credentials', description='Credentials requested', score=30,
            evidence='verify your password', recommendation='Do not provide credentials.',
        )],
    )
    decision = fuse_analysis_results(
        rule, 'legitimate', 0.2, authenticated_sender=True, strong_malicious_evidence=True,
    )
    assert decision.classification == ThreatClassification.phishing


def test_low_severity_rules_cannot_combine_with_ml_alone_into_phishing():
    rule = AnalysisResult(
        classification='safe', risk_score=8, confidence=0.65, engine_version='rules-v3.1.0',
        signals=[ThreatSignal(
            code='url_sender_domain_mismatch', category='url', severity='low',
            title='Mismatch', description='Different domain', score=8,
            evidence='example', recommendation='Verify.',
        )],
    )
    decision = fuse_analysis_results(rule, 'phishing', 0.99)
    assert decision.classification == ThreatClassification.suspicious


def test_marginal_band_is_configurable_and_does_not_lower_threshold():
    rule = AnalysisResult(
        classification='safe', risk_score=5, confidence=0.60, engine_version='rules-v3.1.0',
        signals=[ThreatSignal(
            code='header_missing_authentication', category='header', severity='low',
            title='Missing authentication', description='Authentication unavailable', score=5,
            evidence='Authentication-Results absent', recommendation='Verify.',
        )],
    )
    inside = fuse_analysis_results(
        rule, 'phishing', 0.531410, ml_threshold=0.50, marginal_alert_band=0.04,
        marginal_alert_eligible=True,
    )
    outside = fuse_analysis_results(
        rule, 'phishing', 0.531410, ml_threshold=0.50, marginal_alert_band=0.02,
        marginal_alert_eligible=True,
    )
    assert inside.classification == ThreatClassification.safe
    assert inside.limited_authentication_evidence is True
    assert outside.classification == ThreatClassification.suspicious


@pytest.mark.parametrize('mutation', ['auth_fail', 'unrelated_link', 'credential_request', 'hidden_destination'])
def test_marginal_exception_rejects_corroborating_malicious_evidence(mutation):
    raw = (FIXTURE_DIR / 'gmail_inbox_welcome_missing_auth.eml').read_text(encoding='utf-8')
    if mutation == 'auth_fail':
        raw = raw.replace('MIME-Version:', 'Authentication-Results: mx.example.net; spf=fail; dkim=fail; dmarc=fail\nMIME-Version:')
    elif mutation == 'unrelated_link':
        raw = raw.replace('https://support.google.com/mail/answer/intro', 'https://unrelated.example/login')
    elif mutation == 'credential_request':
        raw = raw.replace('Welcome to Gmail.', 'Welcome to Gmail. Please verify your password.')
    else:
        raw = raw.replace(
            '<a href="https://support.google.com/mail/answer/intro">Explore Gmail help</a>',
            '<a href="https://unrelated.example/login">https://support.google.com</a>',
        )
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label='phishing', phishing_probability=0.531410, legitimate_probability=0.468590,
        )
        service.model_version = 'ml-english-template-robust-v3.0.0'
        service.decision_threshold = 0.5
        result = pipeline.run(raw)
    assert result.decision.classification != ThreatClassification.safe
    assert result.decision.limited_authentication_evidence is False


def test_markup_urls_and_encoding_controls_do_not_affect_visible_text_features():
    visible = 'Your monthly newsletter is ready for review at your convenience.'
    markup = '<style>.PASSWORD{background:url(http://x.example/VERIFY_ACCOUNT)}</style>'
    assert analyze_content('Newsletter', visible, '', None) == []
    # Raw markup is deliberately not passed by the pipeline; this guards the intended contract.
    parsed = parse_email(f'From: a@example.com\nSubject: Newsletter\nContent-Type: text/html\n\n<html>{markup}<body>{visible}</body></html>')
    assert 'PASSWORD' not in parsed.body_visible_text
    assert analyze_content(parsed.subject, parsed.body_text, parsed.body_visible_text, None) == []
