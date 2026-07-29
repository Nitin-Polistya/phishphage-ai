"""Deterministic, privacy-safe analysis of actionable mailto destinations."""

from __future__ import annotations

from app.analyzers.brand_identity import BrandClaimAssessment
from app.schemas.analysis import ThreatSeverity, ThreatSignal


def analyze_mailto_destinations(parsed_email, assessment: BrandClaimAssessment | None) -> list[ThreatSignal]:
    """Return a concern only when a mailto action has meaningful context.

    Mailto is not inherently malicious. A supported brand claim, sensitive
    action language, and an unrelated public mailbox are required before a
    high-concern finding is emitted.
    """
    evidence = list(getattr(parsed_email, 'mailto_evidence', []) or [])
    if not evidence:
        return []

    findings: list[ThreatSignal] = []
    malformed_count = sum(1 for item in evidence if getattr(item, 'malformed', False))
    if malformed_count:
        findings.append(ThreatSignal(
            code='mailto_malformed',
            category='action',
            severity=ThreatSeverity.low,
            title='Malformed email action destination',
            description='A mailto action was present but did not contain a verifiable recipient domain.',
            score=0,
            evidence='mailto destination unavailable',
            recommendation='Do not use message actions until the sender and destination are independently verified.',
            source_engine='rules',
            evidence_type='parser_evidence',
            user_impact='The action destination could not be inspected locally.',
            tone='informational',
            contributes_to_score=False,
            provenance='local mailto parser',
        ))

    if assessment is None:
        return findings

    accepted_domains = set()
    from app.analyzers.brand_identity import BRAND_DOMAIN_FAMILIES
    accepted_domains.update(BRAND_DOMAIN_FAMILIES.get(assessment.brand, ()))
    domains = sorted({
        domain
        for item in evidence
        for domain in (getattr(item, 'destination_domains', []) or [])
    })
    external_domains = [domain for domain in domains if domain not in accepted_domains]
    if not external_domains:
        return findings

    action_types = {getattr(item, 'action_type', 'unknown') for item in evidence}
    sensitive_action = assessment.sensitive_claim or bool(action_types & {'report', 'security', 'payment'})
    personal_provider = any(domain in {
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com',
        'live.com', 'yahoo.com', 'icloud.com', 'aol.com',
    } for domain in external_domains)
    if not sensitive_action and not personal_provider:
        return findings

    severity = ThreatSeverity.high if assessment.sensitive_claim and personal_provider else ThreatSeverity.medium
    concern = 'high_concern' if severity == ThreatSeverity.high else 'review'
    domain_text = ', '.join(external_domains[:4])
    findings.append(ThreatSignal(
        code='mailto_destination_mismatch',
        category='action',
        severity=severity,
        title='Security action redirects to an unrelated email address',
        description=(
            f'The message claims to represent {assessment.brand.title()}, but the action opens an email to '
            f'{domain_text}, unrelated to the recognized {assessment.brand.title()} domain family.'
        ),
        score=0,
        evidence=f'claimed_brand={assessment.brand}; destination_domains={domain_text}; action={assessment.claim_source}',
        recommendation=(
            'Do not click links, buttons, or reply to addresses in the message. Open the claimed service directly '
            'through a trusted bookmark or typed official address and verify the alert independently.'
        ),
        source_engine='decision_safety',
        evidence_type='decision_safety_finding',
        user_impact='Replying may disclose information to an unrelated mailbox controlled outside the claimed organization.',
        tone=concern,
        confidence=0.94 if severity == ThreatSeverity.high else 0.78,
        mapped_title='Security action redirects to an unrelated email address',
        mapped_description='The message claims a trusted organization but directs the action to an unrelated mailbox domain.',
        contributes_to_score=False,
        provenance='offline mailto destination/domain comparison',
    ))
    return findings
