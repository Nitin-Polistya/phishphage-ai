"""Offline, conservative claimed-brand and sender-domain explainability."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from app.schemas.analysis import ThreatSeverity, ThreatSignal
from app.services.domain_utils import registrable_domain


# Keep this mapping deliberately small and reviewable. It describes domain
# families, not a claim that every message sent through a family is safe.
BRAND_DOMAIN_FAMILIES: dict[str, frozenset[str]] = {
    'amazon': frozenset({'amazon.com', 'amazonaws.com', 'amazonpay.com'}),
    'apple': frozenset({'apple.com', 'icloud.com'}),
    'google': frozenset({'google.com', 'gmail.com', 'googleapis.com'}),
    'github': frozenset({'github.com', 'githubusercontent.com'}),
    'microsoft': frozenset({'microsoft.com', 'office.com', 'outlook.com', 'live.com', 'sharepoint.com', 'azure.com', 'windows.com'}),
    'paypal': frozenset({'paypal.com'}),
    'facebook': frozenset({'facebook.com', 'meta.com', 'instagram.com'}),
    'linkedin': frozenset({'linkedin.com'}),
    'dropbox': frozenset({'dropbox.com'}),
    'netflix': frozenset({'netflix.com'}),
    'bank of america': frozenset({'bankofamerica.com'}),
    'chase': frozenset({'chase.com'}),
    'irs': frozenset({'irs.gov'}),
    'us government': frozenset({'usa.gov', 'gov'}),
}

SENSITIVE_CLAIM_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('account_security', ('account security', 'security alert', 'security notice', 'unusual sign in', 'unusual sign-in', 'unusual activity', 'new sign in', 'new sign-in')),
    ('password_reset', ('password reset', 'reset your password', 'change your password', 'password expires')),
    ('payment', ('payment', 'invoice', 'billing', 'card payment', 'transaction')),
    ('banking', ('bank', 'wire transfer', 'account balance', 'beneficiary')),
    ('government_legal', ('government notice', 'tax notice', 'legal notice', 'court notice', 'immigration')),
    ('cloud_admin', ('cloud admin', 'administrator alert', 'admin alert', 'tenant alert', 'azure alert')),
    ('cryptocurrency_withdrawal', ('crypto withdrawal', 'cryptocurrency withdrawal', 'wallet withdrawal')),
    ('identity_verification', ('identity verification', 'verify your identity', 'identity check')),
)


@dataclass(frozen=True)
class BrandClaimAssessment:
    brand: str
    sender_domain: str | None
    sender_domain_matches: bool
    sensitive_category: str | None
    claim_source: str
    confidence: float
    third_party_authenticated: bool = False

    @property
    def sensitive_claim(self) -> bool:
        return self.sensitive_category is not None


def normalize_claim_text(value: str | None) -> str:
    """Normalize display names and message claims without network access."""
    normalized = unicodedata.normalize('NFKC', value or '').casefold()
    return re.sub(r'\s+', ' ', normalized).strip()


def _brand_claim(text: str, brand: str) -> bool:
    # Phrase brands are matched as words; punctuation and Unicode variants are
    # normalized before this point. This avoids substring claims such as
    # "googler".
    escaped = re.escape(brand)
    return re.search(rf'(?<![\w]){escaped}(?![\w])', text, re.IGNORECASE) is not None


def sensitive_claim_category(text: str) -> str | None:
    normalized = normalize_claim_text(text)
    for category, phrases in SENSITIVE_CLAIM_PATTERNS:
        if any(phrase in normalized for phrase in phrases):
            return category
    return None


def assess_claimed_brand(
    *,
    display_name: str | None,
    subject: str | None,
    body: str | None,
    sender_domain: str | None,
    authenticated_sender: bool = False,
) -> BrandClaimAssessment | None:
    display = normalize_claim_text(display_name)
    subject_text = normalize_claim_text(subject)
    body_text = normalize_claim_text(body)
    combined = ' '.join(part for part in (subject_text, body_text) if part)

    for brand, accepted_domains in BRAND_DOMAIN_FAMILIES.items():
        if display and _brand_claim(display, brand):
            source, confidence = 'sender_display_name', 0.97
        elif subject_text and _brand_claim(subject_text, brand):
            source, confidence = 'subject_claim', 0.92
        elif combined and _brand_claim(combined, brand) and sensitive_claim_category(combined):
            source, confidence = 'sensitive_body_claim', 0.86
        else:
            continue

        normalized_sender = registrable_domain(sender_domain)
        if not normalized_sender:
            # A claimed brand cannot be compared to an unavailable sender
            # domain. Keep the state uncertain instead of fabricating a
            # mismatch finding.
            return None
        matches = normalized_sender in accepted_domains if normalized_sender else False
        sensitive = sensitive_claim_category(' '.join((subject_text, body_text, display)))
        # An aligned authentication result can explain a bulk-delivery path,
        # but it does not turn a clear sensitive claim into a verified identity.
        if matches:
            return BrandClaimAssessment(brand, normalized_sender, True, sensitive, source, 1.0, authenticated_sender)
        return BrandClaimAssessment(brand, normalized_sender, False, sensitive, source, confidence, authenticated_sender)
    return None


def brand_identity_signals(assessment: BrandClaimAssessment | None) -> list[ThreatSignal]:
    if assessment is None or assessment.sender_domain_matches:
        return []

    sensitive_text = (
        f' The message also contains a {assessment.sensitive_category.replace("_", " ")} request.'
        if assessment.sensitive_category else ''
    )
    third_party_context = assessment.third_party_authenticated and not assessment.sensitive_claim
    severity = ThreatSeverity.medium if third_party_context else ThreatSeverity.high
    confidence = 0.66 if third_party_context else assessment.confidence
    description = (
        f'The message claims to represent {assessment.brand.title()}, but the sender domain '
        f'"{assessment.sender_domain or "unavailable"}" is not a recognized {assessment.brand.title()} domain.'
        f'{sensitive_text}'
    )
    signal = ThreatSignal(
        code='identity_claim_sender_domain_mismatch',
        category='identity',
        severity=severity,
        title='Claimed organization does not match sender domain',
        description=description,
        score=0,
        evidence=f'brand={assessment.brand}; sender_domain={assessment.sender_domain or "unavailable"}; source={assessment.claim_source}',
        recommendation=(
            'Do not click message links or provide credentials or codes. Open the claimed service using a trusted bookmark or manually typed official address, and verify the sender through an independent channel.'
        ),
        source_engine='rules',
        evidence_type='parser_evidence',
        user_impact='The claimed organization cannot be verified from the sender identity alone.',
        tone='high_concern' if not third_party_context else 'review',
        confidence=confidence,
        mapped_title='Claimed organization does not match sender domain',
        mapped_description=description,
        contributes_to_score=False,
        provenance='offline claimed-brand/domain-family mapping',
    )
    findings = [signal]
    if assessment.sensitive_claim:
        findings.append(ThreatSignal(
            code='sensitive_brand_claim_requires_review',
            category='identity',
            severity=ThreatSeverity.high,
            title='Sensitive claimed-brand request requires review',
            description='The message combines a sensitive action request with a claimed organization whose sender domain is not recognized.',
            score=0,
            evidence=f'brand={assessment.brand}; category={assessment.sensitive_category}',
            recommendation='Do not click links or provide credentials, payment details, or codes. Use the official service directly and verify through an independent channel.',
            source_engine='decision_safety',
            evidence_type='decision_safety_finding',
            user_impact='A false reassurance could lead to credential, payment, or identity loss.',
            tone='high_concern',
            confidence=assessment.confidence,
            mapped_title='Sensitive request from an unverified claimed organization',
            mapped_description='Review is required before taking the requested action.',
            contributes_to_score=False,
            provenance='offline sensitive-claim policy',
        ))
    return findings
