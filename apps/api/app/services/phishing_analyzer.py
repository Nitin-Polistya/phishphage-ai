"""Orchestrator that runs analyzers and produces AnalysisResult."""

from __future__ import annotations

import re
from typing import List

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.feature_engineering import extract_features
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.header_analyzer import evaluate_authentication
from app.analyzers.url_analyzer import analyze_urls
from app.analyzers.brand_identity import assess_claimed_brand, brand_identity_signals
from app.analyzers.mailto_analyzer import analyze_mailto_destinations
from app.schemas.analysis import AnalysisResult, ThreatSignal, ThreatClassification
from app.schemas.analysis import ThreatSeverity
from app.schemas.email import AnalysisInputMode
from app.services.risk_scoring import calculate_risk_score, classify_risk_score, calculate_confidence


ENGINE_VERSION = 'rules-v3.1.0'


def _recommendations_from_signals(signals: List[ThreatSignal]) -> List[str]:
    recs = [signal.recommendation for signal in sorted(
        signals,
        key=lambda signal: ({ThreatSeverity.high: 0, ThreatSeverity.medium: 1, ThreatSeverity.low: 2}[signal.severity], signals.index(signal)),
    ) if signal.recommendation]
    if not recs:
        return ['Report or delete the message according to your local policy.']
    return normalize_recommendations(recs)


def normalize_recommendations(recommendations: List[str]) -> List[str]:
    """Deduplicate semantically equivalent advice with stable severity ordering."""
    recs = [re.sub(r'\s+', ' ', recommendation).strip() for recommendation in recommendations if recommendation and recommendation.strip()]
    if not recs:
        return ['Report or delete the message according to your local policy.']

    def recommendation_key(value: str) -> str:
        lowered = re.sub(r'\s+', ' ', value.casefold())
        if 'do not click' in lowered or 'do not use the supplied action' in lowered:
            return 'do_not_interact'
        if any(token in lowered for token in ('credential', 'password', 'security code', 'one-time code', 'otp')):
            return 'protect_secrets'
        if 'official service' in lowered or 'trusted bookmark' in lowered or 'manually typed official' in lowered or 'claimed service directly' in lowered or 'open the service independently' in lowered:
            return 'open_official_service'
        if any(token in lowered for token in ('independent channel', 'separate channel', 'known requester', 'verify the sender')):
            return 'verify_independently'
        if any(token in lowered for token in ('report the email', 'report or delete', 'security team')):
            return 'report_or_delete'
        return lowered

    canonical = {
        'do_not_interact': 'Do not click links, buttons, or reply to addresses in the message.',
        'protect_secrets': 'Do not send credentials, codes, payment details, or account information.',
        'open_official_service': 'Open the official service directly through a trusted bookmark or typed official address.',
        'verify_independently': 'Verify the request through an independent channel before taking action.',
        'report_or_delete': 'Report or delete the message according to your local policy.',
    }
    seen: set[str] = set()
    out: list[str] = []
    for recommendation in recs:
        key = recommendation_key(recommendation)
        if key in seen:
            continue
        seen.add(key)
        out.append(canonical.get(key, recommendation))
        if len(out) == 5:
            break
    return out


def _attachment_signals(attachments) -> List[ThreatSignal]:
    executable = {'.exe', '.scr', '.com', '.bat', '.cmd', '.msi', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.ps1', '.hta', '.lnk'}
    macro = {'.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm'}
    archives = {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'}
    benign_decoys = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'txt'}
    suspicious_words = {'urgent', 'invoice', 'payment', 'password', 'payroll', 'confidential', 'scan', 'receipt'}
    findings: dict[str, list[str]] = {}

    for attachment in attachments or []:
        filename = (attachment.filename or '').strip()
        lowered = filename.lower().rstrip('. ')
        suffixes = [f'.{part}' for part in lowered.split('.')[1:]] if '.' in lowered else []
        final_extension = suffixes[-1] if suffixes else (attachment.extension or '').lower()
        if final_extension in executable | macro | archives:
            findings.setdefault('attachment_risky_extension', []).append(filename or 'unnamed attachment')
        if final_extension in executable:
            findings.setdefault('attachment_executable', []).append(filename or 'unnamed attachment')
        if final_extension in macro:
            findings.setdefault('attachment_office_macro', []).append(filename)
        if len(suffixes) >= 2 and suffixes[-2].lstrip('.') in benign_decoys and final_extension in executable | macro | archives:
            findings.setdefault('attachment_double_extension', []).append(filename)
        if sum(extension in archives for extension in suffixes) >= 2 or any(
            token in lowered for token in ('.zip.zip', '.rar.zip', '.7z.zip', 'nested_archive')
        ):
            findings.setdefault('attachment_nested_archive', []).append(filename)
        stem_tokens = set(re.findall(r'[a-z]+', lowered.rsplit('.', 1)[0]))
        if stem_tokens & suspicious_words and (final_extension in executable | macro | archives):
            findings.setdefault('attachment_suspicious_name', []).append(filename)

    specs = {
        'attachment_risky_extension': (ThreatSeverity.medium, 'Risky attachment type', 'The filename extension permits executable, active, or concealed content.', 12),
        'attachment_executable': (ThreatSeverity.high, 'Executable attachment', 'The filename has an extension capable of running code.', 34),
        'attachment_office_macro': (ThreatSeverity.high, 'Macro-enabled Office attachment', 'The Office filename indicates that embedded macros are permitted.', 28),
        'attachment_double_extension': (ThreatSeverity.high, 'Deceptive double extension', 'The filename uses a familiar document extension before a risky final extension.', 30),
        'attachment_nested_archive': (ThreatSeverity.medium, 'Nested archive indicator', 'The filename suggests an archive packaged inside another archive.', 18),
        'attachment_suspicious_name': (ThreatSeverity.medium, 'Suspicious attachment naming', 'The filename combines pressure or business bait with a risky file type.', 14),
    }
    return [ThreatSignal(
        code=code, category='attachment', severity=specs[code][0], title=specs[code][1],
        description=specs[code][2], score=specs[code][3], evidence=', '.join(names[:5]),
        recommendation='Do not open the attachment; verify it with the sender and have security tooling inspect it.',
    ) for code, names in findings.items()]


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
        recommendation='No action is required for this fact alone; consider it only with other evidence.',
        source_engine='rules',
        evidence_type='parser_evidence',
        tone='informational',
        user_impact='This is contextual metadata and does not indicate a threat by itself.',
        contributes_to_score=False,
        provenance='normalized sender and recipient fields',
    )]


def _decision_safety_signals(parsed_email, authentication) -> List[ThreatSignal]:
    """Return non-scoring findings for evidence contradictions and identity claims."""
    sender_domain = None
    if parsed_email.sender:
        sender_domain = str(parsed_email.sender.address).rsplit('@', 1)[-1]
    assessment = assess_claimed_brand(
        display_name=parsed_email.sender.name if parsed_email.sender else None,
        subject=parsed_email.subject,
        body=' '.join(filter(None, [parsed_email.body_text, parsed_email.body_visible_text])),
        sender_domain=sender_domain,
        authenticated_sender=authentication.trusted_sender,
    )
    findings = brand_identity_signals(assessment)
    findings.extend(analyze_mailto_destinations(parsed_email, assessment))
    if parsed_email.link_language_present and parsed_email.actual_url_count == 0:
        findings.append(ThreatSignal(
            code='url_destination_unverified',
            category='decision_safety',
            severity=ThreatSeverity.medium,
            title='Link destination could not be verified',
            description='The message appears to request link interaction, but the destination could not be verified.',
            score=0,
            evidence=parsed_email.url_extraction_reason or 'link_language_without_url',
            recommendation='Do not click message links. Open the claimed service directly using a trusted bookmark or manually typed official address.',
            source_engine='decision_safety',
            evidence_type='decision_safety_finding',
            user_impact='The requested destination is not available for local inspection.',
            tone='high_concern',
            confidence=0.9,
            mapped_title='Destination could not be verified',
            mapped_description='The message appears to request link interaction, but the destination could not be verified.',
            contributes_to_score=False,
            provenance='local URL extraction metadata',
        ))
    return findings


def analyze_parsed_email(parsed_email, input_mode: AnalysisInputMode = AnalysisInputMode.raw_email) -> AnalysisResult:
    """Main orchestration function.

    - parsed_email is expected to be the ParsedEmail model from the parser module.
    - This function calls content, url, and header analyzers, deduplicates signals,
      computes risk score, classification, confidence, and recommendations.
    """
    content_signals = analyze_content(
        subject=parsed_email.subject,
        body_text=parsed_email.body_text,
        body_html=getattr(parsed_email, 'body_visible_text', ''),
        sender_name=(parsed_email.sender.name if getattr(parsed_email, 'sender', None) else None)
    )

    url_list = getattr(parsed_email, 'extracted_urls', []) or []
    sender_domain = None
    try:
        sender_domain = parsed_email.sender.address.split('@')[-1] if parsed_email.sender and parsed_email.sender.address else None
    except Exception:
        sender_domain = None

    headers = getattr(parsed_email, 'headers', {}) or {}
    sender_addr = parsed_email.sender.address if parsed_email.sender else None
    authentication = evaluate_authentication(headers, sender_addr)
    strong_action_context = any(signal.code in {
        'content_credential_request', 'content_payment_request', 'content_mfa_bypass',
        'content_account_verification', 'content_fear_tactics', 'content_banking_alert',
    } for signal in content_signals)

    url_signals = analyze_urls(
        url_list,
        sender_domain=sender_domain,
        html_links=getattr(parsed_email, 'html_links', []) or [],
        url_evidence=getattr(parsed_email, 'url_evidence', []) or [],
        authenticated_sender=authentication.trusted_sender,
        strong_action_context=strong_action_context,
    )

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

    safety_signals = _decision_safety_signals(parsed_email, authentication)

    # Combine signals and deduplicate by code. Safety findings are intentionally
    # non-scoring; they gate presentation without changing the approved model or
    # the deterministic risk score.
    combined = {s.code: s for s in (
        content_signals + url_signals + header_signals + attachment_signals + metadata_signals + safety_signals
    )}
    signals = list(combined.values())

    risk = calculate_risk_score(signals)
    classification = classify_risk_score(risk)
    confidence = calculate_confidence(risk, signals)

    recommendations = _recommendations_from_signals(signals)
    engineered_features, feature_explanations, feature_evidence = extract_features(parsed_email)

    return AnalysisResult(
        classification=ThreatClassification(classification),
        risk_score=risk,
        confidence=confidence,
        signals=signals,
        recommendations=recommendations,
        engine_version=ENGINE_VERSION,
        engineered_features=engineered_features,
        feature_explanations=feature_explanations,
        feature_evidence=feature_evidence,
    )
