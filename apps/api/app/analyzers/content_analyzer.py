"""Explainable phrase and intent analysis for phishing content."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.schemas.analysis import ThreatSeverity, ThreatSignal


@dataclass(frozen=True)
class ContentRule:
    code: str
    severity: ThreatSeverity
    title: str
    description: str
    score: int
    phrases: tuple[str, ...]
    recommendation: str


RULES = (
    ContentRule('content_urgency', ThreatSeverity.medium, 'Urgency language detected',
                'The message pressures the recipient to act before verifying the request.', 14,
                ('urgent', 'immediately', 'act now', 'within 24 hours', 'final warning', 'time sensitive',
                 'expires today', 'limited time', 'without delay', 'right away'),
                'Pause and verify the request through a trusted channel before acting.'),
    ContentRule('content_fear_tactics', ThreatSeverity.medium, 'Fear or consequence tactics',
                'The message threatens loss, penalties, or enforcement to force a quick response.', 18,
                ('account suspended', 'account disabled', 'account locked', 'access will be terminated',
                 'unauthorized activity', 'legal action', 'warrant for your arrest', 'avoid prosecution',
                 'penalty will be charged', 'services will be disconnected'),
                'Do not respond under pressure; confirm the claim using official contact details.'),
    ContentRule('content_credential_request', ThreatSeverity.high, 'Credential harvesting language',
                'The message asks for passwords, sign-in details, or other authentication secrets.', 30,
                ('verify your password', 'confirm your password', 'enter credentials', 'login credentials',
                 'sign in to continue', 'validate your account', 'update password', 'reply with your password',
                 'provide your password', 'confirm login'),
                'Do not enter or send credentials; open the service from a known bookmark instead.'),
    ContentRule('content_payment_request', ThreatSeverity.medium, 'Unusual payment request',
                'The message requests a payment or transfer using language common in payment fraud.', 20,
                ('payment required', 'wire transfer', 'bank transfer', 'send payment', 'remit payment',
                 'outstanding balance', 'change of bank details', 'new bank account', 'payment details changed'),
                'Confirm payment instructions with the known requester using a separate channel.'),
    ContentRule('content_fake_invoice', ThreatSeverity.medium, 'Suspicious invoice language',
                'The message presents an unexpected invoice, overdue notice, or purchase document.', 18,
                ('invoice overdue', 'unpaid invoice', 'past due invoice', 'attached invoice', 'invoice attached',
                 'purchase order attached', 'review the invoice', 'outstanding invoice'),
                'Validate the invoice in the organization\'s accounting system before opening files or paying.'),
    ContentRule('content_fake_job_offer', ThreatSeverity.medium, 'Suspicious job-offer language',
                'The offer uses hiring language associated with advance-fee or identity-theft scams.', 18,
                ('job offer', 'work from home opportunity', 'remote position', 'no interview required',
                 'earn money from home', 'equipment check', 'pay for training', 'hiring immediately'),
                'Verify the role on the employer\'s official careers page and never pay to get a job.'),
    ContentRule('content_banking_alert', ThreatSeverity.medium, 'Suspicious banking alert',
                'The message claims a bank transaction or restriction that requires immediate action.', 20,
                ('bank security alert', 'bank account locked', 'debit card suspended', 'unusual bank transaction',
                 'transaction declined', 'confirm this transaction', 'online banking suspended'),
                'Use the phone number on your card or the official banking app to verify the alert.'),
    ContentRule('content_government_notice', ThreatSeverity.medium, 'Suspicious government notice',
                'The message invokes taxes, benefits, immigration, or law enforcement to demand action.', 20,
                ('tax refund pending', 'tax payment required', 'irs notice', 'social security suspended',
                 'government grant', 'immigration notice', 'customs penalty', 'court summons'),
                'Contact the agency through its official government website; do not use message links.'),
    ContentRule('content_delivery_scam', ThreatSeverity.medium, 'Suspicious delivery message',
                'The message claims a parcel problem and requests a fee or personal details.', 18,
                ('package delivery failed', 'parcel delivery failed', 'reschedule delivery', 'delivery fee',
                 'shipping address required', 'package held', 'customs fee', 'missed delivery'),
                'Check the tracking number directly on the carrier\'s official website.'),
    ContentRule('content_crypto_scam', ThreatSeverity.medium, 'Cryptocurrency scam language',
                'The message promotes a crypto transfer, wallet action, giveaway, or guaranteed return.', 22,
                ('send bitcoin', 'bitcoin payment', 'crypto wallet', 'wallet recovery phrase', 'seed phrase',
                 'crypto giveaway', 'double your crypto', 'guaranteed crypto returns', 'investment mining'),
                'Do not transfer cryptocurrency or disclose wallet recovery information.'),
    ContentRule('content_gift_card_scam', ThreatSeverity.high, 'Gift-card purchase request',
                'The message asks for gift cards or redemption codes, a common irreversible-payment scam.', 28,
                ('buy gift cards', 'purchase gift cards', 'gift card codes', 'scratch the card',
                 'send me the codes', 'itunes cards', 'steam gift card', 'google play cards'),
                'Do not buy or share gift-card codes; verify the requester by phone.'),
    ContentRule('content_account_verification', ThreatSeverity.medium, 'Account verification request',
                'The recipient is directed to verify, restore, unlock, or reactivate an account.', 18,
                ('verify your account', 'account verification required', 'confirm your account',
                 'reactivate your account', 'unlock your account', 'secure your account', 'restore access'),
                'Open the service independently and review account notifications there.'),
    ContentRule('content_mfa_bypass', ThreatSeverity.high, 'MFA bypass request',
                'The message requests a one-time code or asks the recipient to approve an unexpected prompt.', 34,
                ('send the verification code', 'share the verification code', 'send the otp', 'share your otp',
                 'provide the security code', 'approve the sign-in', 'approve the login request',
                 'disable two-factor', 'bypass mfa', 'mfa code'),
                'Never share one-time codes or approve an authentication prompt you did not initiate.'),
    ContentRule('content_impersonation', ThreatSeverity.medium, 'Authority impersonation language',
                'The sender claims to represent a trusted support, security, or payroll team.', 14,
                ('it support', 'security team', 'bank security', 'microsoft support', 'google support',
                 'payroll department', 'chief executive officer', 'ceo request'),
                'Verify the sender through the organization\'s directory or official contact details.'),
    ContentRule('content_suspicious_cta', ThreatSeverity.medium, 'Suspicious call-to-action',
                'The message directs the recipient to click, download, or disclose sensitive information.', 14,
                ('click here', 'open the attachment', 'download now', 'verify now', 'login here',
                 'scan the qr code', 'reply with your'),
                'Do not use the supplied action; navigate to the service independently.'),
)

UPPERCASE_RATIO_THRESHOLD = 0.30
REPEATED_PUNCTUATION_PATTERN = re.compile(r'([!?])\1{2,}')


def _normalize_text(parts: Iterable[str]) -> str:
    return re.sub(r'\s+', ' ', ' '.join(part for part in parts if part)).lower()


def _matching_phrases(text: str, phrases: tuple[str, ...]) -> list[str]:
    return [phrase for phrase in phrases if phrase in text]


def analyze_content(subject: str | None, body_text: str | None, body_html: str | None,
                    sender_name: str | None) -> list[ThreatSignal]:
    del sender_name  # Reserved for future sender-aware language rules.
    text = _normalize_text((subject or '', body_text or '', body_html or ''))
    signals: list[ThreatSignal] = []

    for rule in RULES:
        matches = _matching_phrases(text, rule.phrases)
        if matches:
            signals.append(ThreatSignal(
                code=rule.code, category='content', severity=rule.severity, title=rule.title,
                description=rule.description, score=rule.score, evidence=', '.join(matches[:3]),
                recommendation=rule.recommendation,
            ))

    raw = ' '.join((subject or '', body_text or ''))
    raw_letters = [char for char in raw if char.isalpha()]
    if len(raw_letters) >= 10:
        upper_fraction = sum(char.isupper() for char in raw_letters) / len(raw_letters)
        if upper_fraction > UPPERCASE_RATIO_THRESHOLD:
            signals.append(ThreatSignal(
                code='content_excessive_caps', category='content', severity=ThreatSeverity.low,
                title='Excessive capitalization', description='A high uppercase ratio adds emotional pressure.',
                score=5, evidence=f'uppercase_ratio={upper_fraction:.2f}',
                recommendation='Treat emotional formatting as context and verify the request itself.',
            ))

    if REPEATED_PUNCTUATION_PATTERN.search(raw):
        signals.append(ThreatSignal(
            code='content_excessive_punct', category='content', severity=ThreatSeverity.low,
            title='Excessive punctuation', description='Repeated punctuation is used to amplify urgency.',
            score=4, evidence='three_or_more_repeated_marks',
            recommendation='Do not let urgent formatting replace independent verification.',
        ))

    return signals
