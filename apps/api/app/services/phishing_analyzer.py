"""Orchestrator that runs analyzers and produces AnalysisResult."""

from __future__ import annotations

from typing import List

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.url_analyzer import analyze_urls
from app.schemas.analysis import AnalysisResult, ThreatSignal, ThreatClassification
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


def analyze_parsed_email(parsed_email) -> AnalysisResult:
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

    header_signals = analyze_headers(headers, sender_addr, sender_name, return_path, message_id)

    # Combine signals and deduplicate by code
    combined = {s.code: s for s in (content_signals + url_signals + header_signals)}
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
