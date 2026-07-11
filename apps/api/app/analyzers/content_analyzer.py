"""Content analyzer: detect phishing language patterns in subject and body."""

from __future__ import annotations

import logging
import re
from typing import Iterable

from app.schemas.analysis import ThreatSignal, ThreatSeverity

logger = logging.getLogger(__name__)

# Keyword groups
URGENCY = [
    'urgent', 'immediately', 'act now', 'within 24 hours', 'final warning', 'time sensitive'
]

CREDENTIAL_REQUEST = [
    'verify your password', 'confirm login', 'enter credentials', 'sign in to continue',
    'validate your account', 'update password'
]

ACCOUNT_THREAT = [
    'account suspended', 'account disabled', 'account locked', 'access will be terminated',
    'unauthorized activity'
]

FINANCIAL = [
    'gift card', 'lottery', 'prize', 'refund', 'wire transfer', 'payment required',
    'cryptocurrency', 'bitcoin', 'invoice overdue'
]

IMPERSONATION = [
    'it support', 'security team', 'bank security', 'microsoft support', 'google support',
    'payroll department'
]

SUSPICIOUS_CTA = [
    'click here', 'open the attachment', 'download now', 'verify now', 'login here',
    'reply with your password'
]


UPPERCASE_RATIO_THRESHOLD = 0.30
REPEATED_PUNCTUATION_PATTERN = re.compile(r'([!?])\1{2,}')


def _normalize_text(parts: Iterable[str]) -> str:
    return ' '.join(p for p in parts if p).lower()


def _detect_phrases(text: str, phrases: list[str]) -> list[str]:
    found = []
    for phrase in phrases:
        if phrase in text:
            found.append(phrase)
    return found


def analyze_content(subject: str | None, body_text: str | None, body_html: str | None, sender_name: str | None) -> list[ThreatSignal]:
    """Analyze email content and return a list of ThreatSignal objects.

    This function is deterministic and uses simple phrase matching.
    """
    text = _normalize_text([subject or '', body_text or '', (body_html or '')])
    signals: list[ThreatSignal] = []
    categories_found = set()

    # Urgency
    urgent = _detect_phrases(text, URGENCY)
    if urgent:
        categories_found.add('urgency')
        signals.append(ThreatSignal(
            code='content_urgency',
            category='content',
            severity=ThreatSeverity.medium,
            title='Urgency language detected',
            description='Contains urgency phrases to pressure action',
            score=30,
            evidence=', '.join(urgent[:3])
        ))

    # Credential request
    creds = _detect_phrases(text, CREDENTIAL_REQUEST)
    if creds:
        categories_found.add('credential_request')
        signals.append(ThreatSignal(
            code='content_credential_request',
            category='content',
            severity=ThreatSeverity.high,
            title='Credential request language',
            description='Requests credentials or password updates',
            score=60,
            evidence=', '.join(creds[:3])
        ))

    # Account threat
    acct = _detect_phrases(text, ACCOUNT_THREAT)
    if acct:
        categories_found.add('account_threat')
        signals.append(ThreatSignal(
            code='content_account_threat',
            category='content',
            severity=ThreatSeverity.high,
            title='Account threat language',
            description='Claims account suspension or similar threats',
            score=60,
            evidence=', '.join(acct[:3])
        ))

    # Financial/reward scams
    fin = _detect_phrases(text, FINANCIAL)
    if fin:
        categories_found.add('financial')
        signals.append(ThreatSignal(
            code='content_financial_scam',
            category='content',
            severity=ThreatSeverity.medium,
            title='Financial or reward language',
            description='Mentions prizes, refunds, or financial incentives',
            score=30,
            evidence=', '.join(fin[:3])
        ))

    # Impersonation phrases
    imp = _detect_phrases(text, IMPERSONATION)
    if imp:
        categories_found.add('impersonation')
        signals.append(ThreatSignal(
            code='content_impersonation',
            category='content',
            severity=ThreatSeverity.medium,
            title='Impersonation language',
            description='Mentions organizations or teams commonly impersonated',
            score=30,
            evidence=', '.join(imp[:3])
        ))

    # Suspicious CTA
    cta = _detect_phrases(text, SUSPICIOUS_CTA)
    if cta:
        categories_found.add('cta')
        signals.append(ThreatSignal(
            code='content_suspicious_cta',
            category='content',
            severity=ThreatSeverity.medium,
            title='Suspicious call-to-action',
            description='Contains direct instructions to click or provide credentials',
            score=30,
            evidence=', '.join(cta[:3])
        ))

    # Excessive capitalization
    letters = [c for c in text if c.isalpha()]
    if letters:
        upper_frac = sum(1 for c in letters if c.isupper()) / len(letters) if letters else 0
        # Note: text was lowercased earlier; use raw subject/body for uppercase check
        raw = ' '.join([subject or '', body_text or ''])
        raw_letters = [c for c in raw if c.isalpha()]
        if raw_letters:
            upper_frac = sum(1 for c in raw_letters if c.isupper()) / len(raw_letters)
            if upper_frac > UPPERCASE_RATIO_THRESHOLD:
                signals.append(ThreatSignal(
                    code='content_excessive_caps',
                    category='content',
                    severity=ThreatSeverity.low,
                    title='Excessive capitalization',
                    description='High ratio of uppercase letters in content',
                    score=10,
                    evidence=f'upper_frac={upper_frac:.2f}'
                ))

    # Excessive punctuation
    if REPEATED_PUNCTUATION_PATTERN.search(subject or '') or REPEATED_PUNCTUATION_PATTERN.search(body_text or ''):
        signals.append(ThreatSignal(
            code='content_excessive_punct',
            category='content',
            severity=ThreatSeverity.low,
            title='Excessive punctuation',
            description='Repeated exclamation or question marks detected',
            score=10,
            evidence='repeated_punct'
        ))

    # Deduplicate by code
    unique = {}
    for s in signals:
        unique[s.code] = s

    return list(unique.values())
