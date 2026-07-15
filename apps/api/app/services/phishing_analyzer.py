"""Orchestrator that runs analyzers and produces AnalysisResult."""

from __future__ import annotations

from typing import List

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.url_analyzer import analyze_urls
from app.schemas.analysis import AnalysisResult, ThreatSignal, ThreatClassification
from app.schemas.analysis import ThreatSeverity
from app.schemas.email import AnalysisInputMode
from app.services.risk_scoring import calculate_risk_score, classify_risk_score, calculate_confidence


ENGINE_VERSION = 'rules-v1.0.0'


def _recommendations_from_signals(signals: List[ThreatSignal]) -> List[str]:
    cats = {s.code for s in signals}
    recs: List[str] = []
    if any(c.startswith('url_') for c in cats):
        recs.append('Do not click links in this email.')
    if any('credential' in c or 'login' in c for c in cats):
        recs.append('Do not enter or share passwords or authentication codes.')
    if any(c in ('content_excessive_punct', 'content_excessive_caps') for c in cats):
        recs.append('Verify the sender through a trusted communication channel.')
    if any(c.startswith('content_') and ('attachment' in c or 'attachment' in s.title.lower()) for c, s in [(s.code, s) for s in signals]):
        recs.append('Do not open unexpected attachments.')
    if any(c.startswith('attachment_') for c in cats):
        recs.append('Do not open unexpected attachments.')
    if any(c.startswith('content_impersonation') or c.startswith('header_displayname_impersonation') for c in cats):
        recs.append('Verify the sender via the organization\'s official website or phone number.')
    if not recs:
        recs.append('Report the email to your security team or email provider if suspicious.')
    # Deduplicate while preserving order
    seen = set()
    out = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _attachment_signals(attachments) -> List[ThreatSignal]:
    risky = []
    for attachment in attachments or []:
        if attachment.suspicious_extension:
            risky.append(attachment.filename or 'unnamed attachment')
    if not risky:
        return []
    return [ThreatSignal(
        code='attachment_risky_extension',
        category='attachment',
        severity=ThreatSeverity.high,
        title='Risky attachment extension',
        description='The attachment type can deliver executable code or conceal active content.',
        score=35,
        evidence=', '.join(risky[:5]),
    )]


def _quick_paste_metadata_signals(parsed_email) -> List[ThreatSignal]:
    if not parsed_email.sender or not parsed_email.recipients:
        return []
    sender = str(parsed_email.sender.address).strip().casefold()
    recipient = str(parsed_email.recipients[0].address).strip().casefold()
    if not sender or not recipient or sender != recipient:
        return []
    return [ThreatSignal(
        code='SELF_ADDRESSED_EMAIL',
        category='metadata',
        severity=ThreatSeverity.low,
        title='Sender and recipient are the same',
        description=(
            'The message appears to have been sent to the same address it originated from. '
            'This can be legitimate, such as a self-sent or test email.'
        ),
        score=0,
        evidence=sender,
    )]


def analyze_parsed_email(parsed_email, input_mode: AnalysisInputMode = AnalysisInputMode.raw_email) -> AnalysisResult:
    """Main orchestration function.

    - parsed_email is expected to be the ParsedEmail model from the parser module.
    - This function calls content, url, and header analyzers, deduplicates signals,
      computes risk score, classification, confidence, and recommendations.
    """
    content_signals = analyze_content(
        subject=parsed_email.subject,
        body_text=parsed_email.body_text,
        body_html=parsed_email.body_html,
        sender_name=(parsed_email.sender.name if getattr(parsed_email, 'sender', None) else None)
    )

    url_list = getattr(parsed_email, 'extracted_urls', []) or []
    sender_domain = None
    try:
        sender_domain = parsed_email.sender.address.split('@')[-1] if parsed_email.sender and parsed_email.sender.address else None
    except Exception:
        sender_domain = None

    url_signals = analyze_urls(url_list, sender_domain=sender_domain)

    headers = getattr(parsed_email, 'headers', {}) or {}
    sender_addr = parsed_email.sender.address if parsed_email.sender else None
    sender_name = parsed_email.sender.name if parsed_email.sender else None
    return_path = headers.get('return-path') or headers.get('return_path')
    message_id = parsed_email.message_id

    header_signals = [] if input_mode == AnalysisInputMode.quick_paste else analyze_headers(
        headers, sender_addr, sender_name, return_path, message_id
    )

    attachment_signals = _attachment_signals(getattr(parsed_email, 'attachments', []) or [])
    metadata_signals = (
        _quick_paste_metadata_signals(parsed_email)
        if input_mode == AnalysisInputMode.quick_paste else []
    )

    # Combine signals and deduplicate by code
    combined = {s.code: s for s in (
        content_signals + url_signals + header_signals + attachment_signals + metadata_signals
    )}
    signals = list(combined.values())

    risk = calculate_risk_score(signals)
    classification = classify_risk_score(risk)
    confidence = calculate_confidence(risk, signals)

    recommendations = _recommendations_from_signals(signals)

    return AnalysisResult(
        classification=ThreatClassification(classification),
        risk_score=risk,
        confidence=confidence,
        signals=signals,
        recommendations=recommendations,
        engine_version=ENGINE_VERSION
    )
