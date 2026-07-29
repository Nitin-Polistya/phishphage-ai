"""Synthetic regression coverage for decision-safety presentation gates."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from app.analyzers.brand_identity import assess_claimed_brand, brand_identity_signals
from app.analyzers.header_analyzer import evaluate_authentication
from app.schemas.analysis import ThreatClassification
from app.services.analysis_pipeline import AnalysisPipeline, CURRENT_MODEL_VERSION, CURRENT_RULE_VERSION
from app.services.decision_safety import can_present_safe_verdict
from app.services.email_parser import parse_email


def _run(raw: str, *, prediction: str = 'legitimate', probability: float = 0.1, model_version: str = CURRENT_MODEL_VERSION):
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label=prediction,
            phishing_probability=probability,
            legitimate_probability=1.0 - probability,
        )
        service.model_version = model_version
        service.decision_threshold = 0.5
        return pipeline.run(raw)


COMPLETE_SAFE = (
    'From: Alice <alice@example.com>\nTo: bob@example.net\n'
    'Date: Wed, 29 Jul 2026 10:00:00 +0000\nMessage-ID: <a@example.com>\n'
    'Return-Path: <alice@example.com>\n'
    'Authentication-Results: mx; spf=pass smtp.mailfrom=example.com; '
    'dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n'
    'Subject: Team update\n\nThe meeting is tomorrow.'
)


def test_fresh_complete_safe_email_is_eligible():
    result = _run(COMPLETE_SAFE)
    assert result.decision.classification == ThreatClassification.safe
    assert result.analysis_freshness.value == 'current'
    assert result.analysis_completeness_status.value == 'complete'
    assert result.safe_verdict_allowed is True
    assert result.decision_safety_status.value == 'eligible'
    assert result.presentation_state.value == 'safe'
    assert result.fusion_performed is True
    assert result.engines_completed == ['rules', 'ml', 'fusion']


def test_ml_only_or_missing_ml_never_becomes_safe(tmp_path: Path):
    result = AnalysisPipeline(model_path=tmp_path / 'missing.joblib', ml_required=False).run(COMPLETE_SAFE)
    assert result.ml_analysis.status.value == 'unavailable'
    assert result.safe_verdict_allowed is False
    assert result.presentation_state.value == 'rescan_required'
    assert result.requires_rescan is True
    assert result.fusion_performed is False
    assert result.fusion_reason is None
    assert result.rule_ml_agreement is None
    assert result.fallback_used is True
    assert result.decision_source == 'rules_fallback'


def test_stale_rule_version_requires_rescan():
    from app.services.phishing_analyzer import analyze_parsed_email

    def stale_rules(parsed, input_mode):
        return analyze_parsed_email(parsed, input_mode).model_copy(update={'engine_version': 'rules-v2.0.0'})

    with patch('app.services.analysis_pipeline.analyze_parsed_email', side_effect=stale_rules):
        result = _run(COMPLETE_SAFE)
    assert result.analysis_freshness.value == 'stale'
    assert result.presentation_state.value == 'rescan_required'
    assert result.safe_verdict_allowed is False
    assert 'stale_result' in result.incomplete_reason_codes
    assert result.stale_reason == f'Expected rule engine {CURRENT_RULE_VERSION}; received rules-v2.0.0.'


def test_current_but_partial_source_cannot_present_safe():
    result = _run(
        'From: sender@example.com\nSubject: Routine update\n\nNo action is required.',
        model_version=CURRENT_MODEL_VERSION,
    )
    assert result.analysis_freshness.value == 'current'
    assert result.analysis_completeness.limited_evidence is True
    assert result.analysis_completeness_status.value == 'partial'
    assert result.safe_verdict_allowed is False
    assert result.decision_safety_status.value == 'needs_review'
    assert result.presentation_state.value == 'needs_review'
    assert result.requires_rescan is False
    assert 'input_evidence_partial' in result.incomplete_reason_codes


def test_claimed_microsoft_with_unrelated_domain_is_explained_without_score_fabrication():
    assessment = assess_claimed_brand(
        display_name='Microsoft Security',
        subject='Microsoft unusual sign-in activity',
        body='Review your account security now.',
        sender_domain='access-accsecurity.com',
    )
    findings = brand_identity_signals(assessment)
    codes = {finding.code for finding in findings}
    assert 'identity_claim_sender_domain_mismatch' in codes
    assert 'sensitive_brand_claim_requires_review' in codes
    mismatch = next(finding for finding in findings if finding.code == 'identity_claim_sender_domain_mismatch')
    assert mismatch.severity.value == 'high'
    assert mismatch.score == 0
    assert mismatch.contributes_to_score is False
    assert mismatch.tone == 'high_concern'


def test_recognized_domain_has_no_claimed_brand_mismatch():
    assessment = assess_claimed_brand(
        display_name='Microsoft Security',
        subject='Microsoft unusual sign-in activity',
        body='Review your account security now.',
        sender_domain='account.microsoft.com',
    )
    assert brand_identity_signals(assessment) == []


def test_aligned_third_party_delivery_is_not_automatically_high_concern():
    assessment = assess_claimed_brand(
        display_name='Microsoft Newsletter',
        subject='Microsoft product news',
        body='Read the latest product news.',
        sender_domain='sendgrid.net',
        authenticated_sender=True,
    )
    findings = brand_identity_signals(assessment)
    assert findings
    assert findings[0].severity.value == 'medium'
    assert findings[0].confidence == 0.66


def test_link_language_without_destination_is_partial_and_not_verified():
    parsed = parse_email('From: sender@example.com\nSubject: Account update\n\nClick the link below to review your account.')
    assert parsed.link_language_present is True
    assert parsed.actual_url_count == 0
    assert parsed.url_extraction_status == 'partial'
    assert parsed.url_extraction_reason == 'link_language_without_url'
    result = _run('From: sender@example.com\nSubject: Account update\n\nClick the link below to review your account.')
    assert result.safe_verdict_allowed is False
    assert result.url_extraction_status == 'partial'
    assert 'url_extraction_failed' in result.incomplete_reason_codes


def test_html_anchor_destination_is_extracted_without_rendering():
    parsed = parse_email(
        'From: sender@example.com\nSubject: Update\nContent-Type: text/html\n\n'
        '<a href="https://unrelated.example/login">Microsoft security portal</a>'
    )
    assert parsed.html_anchor_count == 1
    assert parsed.actual_url_count == 1
    assert parsed.url_extraction_status == 'extracted'
    assert parsed.extracted_urls == ['https://unrelated.example/login']


def test_authentication_presence_is_not_a_pass():
    missing = evaluate_authentication({'authentication-results': 'SPF detected DKIM detected DMARC detected'}, 'a@example.com')
    assert {item.state.value for item in missing.evidence} == {'missing'}
    passed = evaluate_authentication(
        {'authentication-results': 'mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com'},
        'a@example.com',
    )
    assert {item.state.value for item in passed.evidence} == {'pass'}
    failed = evaluate_authentication({'authentication-results': 'mx; spf=fail; dkim=fail; dmarc=fail'}, 'a@example.com')
    assert {item.state.value for item in failed.evidence} == {'fail'}


def test_safe_eligibility_function_rejects_stale_and_missing_fusion():
    base = {
        'analysis_freshness': 'current', 'analysis_completeness_status': 'complete',
        'fusion_performed': True, 'engines_completed': ['rules', 'ml'],
        'ml_analysis': {'status': 'available'}, 'rule_analysis': {'signals': []},
        'rule_ml_agreement': 'agreement', 'incomplete_reason_codes': [],
    }
    assert can_present_safe_verdict(base) is True
    assert can_present_safe_verdict({**base, 'analysis_freshness': 'stale'}) is False
    assert can_present_safe_verdict({**base, 'fusion_performed': False}) is False
