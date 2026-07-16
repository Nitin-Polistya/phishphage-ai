"""Coverage for Phase 2 explainable detection enhancements."""

import pytest

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.url_analyzer import analyze_urls
from app.schemas.analysis import ThreatSeverity, ThreatSignal
from app.schemas.email import EmailAttachmentMetadata
from app.services.phishing_analyzer import _attachment_signals
from app.services.risk_scoring import calculate_confidence, calculate_risk_score


def _codes(signals):
    return {signal.code for signal in signals}


@pytest.mark.parametrize(('urls', 'expected'), [
    (['https://paypa1-security.com/login'], 'url_lookalike_domain'),
    (['https://account-check.xyz/login'], 'url_suspicious_tld'),
    (['https://example.com/%252Flogin'], 'url_encoding_trick'),
    (['https://раypal.com/login'], 'url_homograph'),
    (['https://tiny.cc/a'], 'url_shortener'),
    (['https://10.20.30.40/login'], 'url_ip_host'),
    (['https://example.com:8443/login'], 'url_suspicious_port'),
    (['https://safe.example/a', 'http://safe.example/b'], 'url_mixed_transport'),
])
def test_enhanced_url_rules(urls, expected):
    assert expected in _codes(analyze_urls(urls))


@pytest.mark.parametrize(('text', 'expected'), [
    ('Final warning: act now or legal action will begin.', 'content_fear_tactics'),
    ('Send payment by wire transfer to our new bank account.', 'content_payment_request'),
    ('Please review the attached invoice. It is past due.', 'content_fake_invoice'),
    ('Remote position, no interview required. Pay for training.', 'content_fake_job_offer'),
    ('Bank security alert: confirm this transaction.', 'content_banking_alert'),
    ('IRS notice: tax payment required immediately.', 'content_government_notice'),
    ('Package delivery failed. Pay the delivery fee.', 'content_delivery_scam'),
    ('Send bitcoin to this crypto wallet for guaranteed crypto returns.', 'content_crypto_scam'),
    ('Buy gift cards and send me the codes.', 'content_gift_card_scam'),
    ('Account verification required. Verify your account.', 'content_account_verification'),
    ('Approve the sign-in and send the OTP.', 'content_mfa_bypass'),
])
def test_enhanced_content_intents(text, expected):
    assert expected in _codes(analyze_content(None, text, None, None))


def test_header_identity_authentication_and_consistency_rules():
    headers = {
        'Reply-To': 'responses@other.example',
        'Return-Path': '<bounce@mailer.example>',
        'Received': 'from relay.example',
        'Authentication-Results': 'mx; spf=softfail; dkim=fail; dmarc=fail',
    }
    signals = analyze_headers(headers, 'notice@paypal-security.example', 'PayPal Support', None, 'invalid-id')
    codes = _codes(signals)
    assert {
        'header_replyto_mismatch', 'header_displayname_impersonation', 'header_invalid_message_id',
        'header_spf_inconclusive', 'header_dkim_fail', 'header_dmarc_fail',
        'header_returnpath_mismatch',
    } <= codes


def test_missing_authentication_is_contextual_when_transport_headers_exist():
    signals = analyze_headers({'Received': 'from relay.example'}, 'a@example.com', 'Alice', None, '<1@example.com>')
    finding = next(signal for signal in signals if signal.code == 'header_missing_authentication')
    assert finding.severity == ThreatSeverity.low
    assert finding.score < 10


def test_attachment_filename_rules_are_metadata_only():
    attachments = [
        EmailAttachmentMetadata(filename='invoice.pdf.exe', content_type='application/octet-stream', size_bytes=1),
        EmailAttachmentMetadata(filename='payroll.docm', content_type='application/msword', size_bytes=2),
        EmailAttachmentMetadata(filename='urgent.zip.zip', content_type='application/zip', size_bytes=3),
    ]
    codes = _codes(_attachment_signals(attachments))
    assert {
        'attachment_risky_extension', 'attachment_executable', 'attachment_double_extension',
        'attachment_office_macro', 'attachment_nested_archive', 'attachment_suspicious_name',
    } <= codes


def test_single_weak_rule_cannot_trigger_phishing_but_diverse_evidence_combines():
    weak = ThreatSignal(code='url_insecure_scheme', category='url', severity='low', title='HTTP',
                        description='HTTP used', score=8, evidence='http://example.com', recommendation='Avoid it.')
    medium = [
        ThreatSignal(code='content_payment_request', category='content', severity='medium', title='Payment',
                     description='Payment requested', score=24, evidence='wire transfer', recommendation='Verify.'),
        ThreatSignal(code='header_replyto_mismatch', category='header', severity='medium', title='Mismatch',
                     description='Reply-To differs', score=22, evidence='other.example', recommendation='Verify.'),
        ThreatSignal(code='url_shortener', category='url', severity='medium', title='Short link',
                     description='Destination hidden', score=20, evidence='bit.ly', recommendation='Avoid it.'),
    ]
    assert calculate_risk_score([weak]) < 30
    assert calculate_risk_score(medium) >= 70
    assert calculate_confidence(calculate_risk_score(medium), medium) > calculate_confidence(8, [weak])


def test_every_emitted_finding_is_actionable_and_explainable():
    signals = (
        analyze_urls(['http://paypa1-security.xyz/%252Flogin'])
        + analyze_content('Urgent', 'Buy gift cards and send me the codes.', None, None)
        + analyze_headers({'Received': 'relay'}, 'a@example.com', 'Alice', None, None)
    )
    assert signals
    for signal in signals:
        assert signal.title.strip()
        assert signal.description.strip()
        assert signal.evidence and signal.evidence.strip()
        assert signal.severity
        assert signal.recommendation.strip()
