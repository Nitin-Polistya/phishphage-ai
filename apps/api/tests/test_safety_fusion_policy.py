"""Phase I.4D evidence-floor, mailto, tracking, and authentication regressions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.analyzers.header_analyzer import evaluate_authentication
from app.schemas.analysis import AnalysisResult, ThreatClassification, ThreatSeverity, ThreatSignal
from app.services.analysis_pipeline import AnalysisPipeline, CURRENT_MODEL_VERSION
from app.services.decision_engine import fuse_analysis_results
from app.services.email_parser import parse_email
from app.services.phishing_analyzer import normalize_recommendations
from app.services.safety_fusion import evaluate_high_confidence_rule_evidence, evaluate_safety_floor


DIAGNOSTIC_EMAIL = """From: Microsoft Security <alerts@access-accsecurity.com>
To: recipient@example.net
Date: Wed, 29 Jul 2026 10:00:00 +0000
Message-ID: <diagnostic@access-accsecurity.com>
Reply-To: security@gmail.com
Return-Path: <bounce@thcultarfdes.co.uk>
Authentication-Results: mx.example; spf=none; dkim=none; dmarc=permerror
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Subject: Microsoft security alert - report the user

<html><body><p>Microsoft security alert. Click here to use the button below to report the user.</p>
<a href="mailto:sotrecognizd@gmail.com?subject=Report%20The%20User&body=Please%20investigate">Report The User</a>
<a href="mailto:sotrecognizd@gmail.com?subject=Report%20The%20User">Report the alert</a>
<a href="mailto:other@gmail.com?subject=Security%20alert">Security support</a>
<img width="1" height="1" src="https://tracking.example/open.gif">
</body></html>"""


def _run(raw: str, probability: float = 0.228571, prediction: str = 'legitimate'):
    pipeline = AnalysisPipeline(ml_required=False)
    with patch('app.services.analysis_pipeline.LocalInferenceService') as mock_class:
        service = mock_class.return_value
        service.predict.return_value = MagicMock(
            predicted_label=prediction,
            phishing_probability=probability,
            legitimate_probability=1.0 - probability,
        )
        service.model_version = CURRENT_MODEL_VERSION
        service.decision_threshold = 0.5
        return pipeline.run(raw)


def _signal(code: str, category: str, score: int, severity: ThreatSeverity = ThreatSeverity.medium):
    return ThreatSignal(
        code=code, category=category, severity=severity, title=code,
        description=code, score=score, recommendation='Verify independently.',
    )


def _rule(score: int, signals: list[ThreatSignal], classification: ThreatClassification = ThreatClassification.suspicious):
    return AnalysisResult(
        classification=classification, risk_score=score, confidence=0.8,
        engine_version='rules-v3.1.0', signals=signals,
    )


def test_diagnostic_strong_multi_family_evidence_applies_floor_and_preserves_ml_probability():
    result = _run(DIAGNOSTIC_EMAIL)
    assert result.ml_phishing_probability == 0.228571
    assert result.rule_raw_score >= 70
    assert result.rule_ml_agreement.value == 'disagreement'
    assert result.safe_verdict_allowed is False
    assert result.decision.safety_floor_applied is True
    assert result.decision.safety_floor_rule_id
    assert result.decision.pre_floor_score is not None
    assert result.decision.post_floor_score is not None
    assert result.decision.post_floor_score >= 80
    assert result.decision.post_floor_score > result.decision.pre_floor_score
    assert result.decision.classification == ThreatClassification.phishing
    assert result.presentation_state.value == 'phishing'
    assert set(result.decision.evidence_families) >= {'identity', 'routing', 'authentication', 'action'}
    assert result.parser.mailto_count == 3
    assert result.parser.actionable_mailto_count == 3
    assert result.parser.mailto_destinations_redacted_or_normalized == ['gmail.com']
    assert result.parser.mailto_external_domain_mismatch is True
    assert result.parser.tracking_pixel_count == 1
    assert result.parser.actionable_url_count == 0
    assert 'mailto_destination_mismatch' in {signal.code for signal in result.rule_analysis.signals}
    assert 'url_tracking_pixel' in {signal.code for signal in result.rule_analysis.signals}
    assert all('sotrecognizd@gmail.com' not in recommendation for recommendation in result.recommendations)
    assert len(result.recommendations) <= 5


def test_duplicate_signals_from_one_family_do_not_trigger_high_floor():
    rule = _rule(90, [_signal('content_credential_request', 'content', 30, ThreatSeverity.high), _signal('content_payment_request', 'content', 20), _signal('content_mfa_bypass', 'content', 34, ThreatSeverity.high)])
    decision = fuse_analysis_results(rule, 'legitimate', 0.23)
    assert decision.safety_floor_applied is False
    assert decision.classification == ThreatClassification.suspicious
    assert decision.evidence_families == ['action']


def test_moderate_two_family_evidence_requires_review_without_phishing_floor():
    rule = _rule(70, [_signal('header_replyto_mismatch', 'header', 20), _signal('content_payment_request', 'content', 20)])
    decision = fuse_analysis_results(rule, 'legitimate', 0.20)
    assert decision.safety_floor_rule_id == 'moderate_correlated_deterministic_evidence'
    assert decision.classification == ThreatClassification.suspicious
    assert decision.post_floor_score >= 60


def test_high_ml_with_weak_rules_remains_model_driven_without_rule_floor():
    rule = _rule(40, [_signal('content_urgency', 'content', 40)], ThreatClassification.suspicious)
    decision = fuse_analysis_results(rule, 'phishing', 0.80)
    assert decision.safety_floor_applied is False
    assert decision.dominant_evidence_source == 'balanced'
    assert decision.classification == ThreatClassification.suspicious


def test_explicit_aligned_authentication_and_official_domain_are_protective():
    parsed = parse_email(
        'From: Microsoft Security <alerts@microsoft.com>\n'
        'To: user@example.net\nDate: Wed, 29 Jul 2026 10:00:00 +0000\n'
        'Message-ID: <official@microsoft.com>\nReturn-Path: <alerts@microsoft.com>\n'
        'Authentication-Results: mx; spf=pass smtp.mailfrom=microsoft.com; '
        'dkim=pass header.d=microsoft.com; dmarc=pass header.from=microsoft.com\n'
        'Subject: Product update\n\nPlease read the product news.'
    )
    rule = _rule(85, [_signal('content_suspicious_cta', 'content', 85)])
    summary = evaluate_high_confidence_rule_evidence(rule.signals, parsed)
    floor = evaluate_safety_floor(rule.risk_score, summary)
    assert summary.aligned_authentication is True
    assert summary.official_brand_domain is True
    assert floor.applied is False


def test_mailto_parser_handles_encoded_subject_multiple_recipients_and_malformed_destination():
    parsed = parse_email(
        'From: Support <support@example.com>\nSubject: Contact support\nContent-Type: text/html\n\n'
        '<a href="mailto:help+tag@example.com,second@example.com?subject=Hello%20there&body=Line%201">Contact support</a>'
        '<a href="mailto:">Broken action</a>'
    )
    assert parsed.mailto_count == 2
    assert parsed.actionable_mailto_count == 1
    assert parsed.mailto_destinations_redacted_or_normalized == ['example.com']
    assert parsed.mailto_evidence[0].recipient_count == 2
    assert parsed.mailto_evidence[0].action_type == 'support'
    assert parsed.mailto_evidence[1].malformed is True


def test_same_domain_support_mailto_is_not_a_mismatch_and_visible_text_mailto_is_not_parsed():
    parsed = parse_email(
        'From: Microsoft Support <support@microsoft.com>\nSubject: Support\nContent-Type: text/html\n\n'
        '<a href="mailto:support@microsoft.com">Contact support</a><p>mailto:outside@gmail.com</p>'
    )
    assert parsed.mailto_count == 1
    assert parsed.mailto_external_domain_mismatch is False
    assert parsed.mailto_destinations_redacted_or_normalized == ['microsoft.com']


def test_tracking_pixel_is_supporting_non_actionable_evidence():
    parsed = parse_email(
        'From: sender@example.com\nSubject: Newsletter\nContent-Type: text/html\n\n'
        '<img width="1" height="1" src="https://tracker.other.example/open.gif">'
    )
    assert parsed.actual_url_count == 1
    assert parsed.actionable_url_count == 0
    assert parsed.tracking_pixel_count == 1
    assert parsed.external_tracking_pixel_count == 1
    evidence = parsed.url_evidence[0]
    assert evidence.source_type.value == 'tracking_pixel'
    assert evidence.user_actionable is False
    assert evidence.security_relevance == 'supporting'


def test_authentication_display_states_are_explicit():
    assessment = evaluate_authentication({
        'Authentication-Results': 'mx; spf=none; dkim=none; dmarc=permerror',
    }, 'alerts@example.com')
    by_mechanism = {item.mechanism: item for item in assessment.evidence}
    assert by_mechanism['spf'].state.value == 'missing'
    assert by_mechanism['spf'].display_label == 'Not authenticated'
    assert by_mechanism['dkim'].display_label == 'Not authenticated'
    assert by_mechanism['dmarc'].state.value == 'inconclusive'
    assert 'permanent error' in (by_mechanism['dmarc'].detail or '')


def test_recommendations_are_stable_semantically_deduplicated_and_capped():
    recommendations = normalize_recommendations([
        'Do not click message links.',
        'Do not click links, buttons, or reply to addresses in the message.',
        'Do not provide credentials or passwords.',
        'Do not send your security code.',
        'Open the official service directly using a trusted bookmark.',
        'Verify the sender through an independent channel.',
        'Report the email to your security team.',
    ])
    assert len(recommendations) == 5
    assert recommendations[0].startswith('Do not click')
    assert recommendations[1].startswith('Do not send')
