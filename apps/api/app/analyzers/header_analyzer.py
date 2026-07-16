"""Deterministic, explainable validation of email identity and authentication headers."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Dict, Optional

from app.schemas.analysis import ThreatSeverity, ThreatSignal


BRAND_DOMAINS = {
    'amazon': ('amazon.',), 'apple': ('apple.',), 'dhl': ('dhl.',), 'dropbox': ('dropbox.',),
    'facebook': ('facebook.', 'meta.'), 'fedex': ('fedex.',), 'google': ('google.',),
    'linkedin': ('linkedin.',), 'microsoft': ('microsoft.', 'office.', 'outlook.'),
    'netflix': ('netflix.',), 'paypal': ('paypal.',), 'ups': ('ups.',), 'yahoo': ('yahoo.',),
}
ROLE_NAMES = ('security team', 'it support', 'payroll department', 'help desk', 'bank security')
MESSAGE_ID_PATTERN = re.compile(r'^<[^<>\s@]+@[^<>\s@]+>$')


def _domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    address = parseaddr(value)[1] or value.strip().strip('<>')
    if '@' not in address:
        return None
    return address.rsplit('@', 1)[1].lower().rstrip('>')


def _signal(code: str, severity: ThreatSeverity, title: str, description: str, score: int,
            evidence: str | None, recommendation: str) -> ThreatSignal:
    return ThreatSignal(code=code, category='header', severity=severity, title=title,
                        description=description, score=score, evidence=evidence,
                        recommendation=recommendation)


def _auth_result(auth: str, mechanism: str) -> str | None:
    match = re.search(rf'\b{mechanism}\s*[=:]\s*([a-z]+)', auth, re.IGNORECASE)
    return match.group(1).lower() if match else None


def analyze_headers(parsed_headers: Dict[str, str], parsed_sender_address: Optional[str],
                    parsed_sender_name: Optional[str], return_path: Optional[str],
                    message_id: Optional[str]) -> list[ThreatSignal]:
    headers = {key.lower().replace('_', '-'): value for key, value in parsed_headers.items()}
    signals: dict[str, ThreatSignal] = {}
    verify_sender = 'Verify the sender using a known address or a separate trusted channel.'

    if not parsed_sender_address:
        return [_signal('header_missing_sender', ThreatSeverity.high, 'Missing sender address',
                        'The message has no parsable From address.', 28, 'From header absent', verify_sender)]

    sender_domain = _domain(parsed_sender_address)
    if not sender_domain:
        signals['header_malformed_sender'] = _signal(
            'header_malformed_sender', ThreatSeverity.high, 'Malformed sender address',
            'The From address is not a valid mailbox identity.', 28, parsed_sender_address, verify_sender)

    reply_to = headers.get('reply-to')
    reply_domain = _domain(reply_to)
    if reply_domain and sender_domain and reply_domain != sender_domain:
        signals['header_replyto_mismatch'] = _signal(
            'header_replyto_mismatch', ThreatSeverity.medium, 'Reply-To domain mismatch',
            'Replies are redirected to a domain different from the visible sender.', 20,
            f'from={sender_domain}, reply_to={reply_domain}',
            'Do not reply until the alternate address is verified with the claimed sender.')

    if parsed_sender_name and sender_domain:
        display_name = parsed_sender_name.lower()
        for brand, allowed_fragments in BRAND_DOMAINS.items():
            if brand in display_name and not any(fragment in sender_domain for fragment in allowed_fragments):
                signals['header_displayname_impersonation'] = _signal(
                    'header_displayname_impersonation', ThreatSeverity.high, 'Display-name impersonation',
                    'The display name claims a well-known organization but the address uses another domain.', 30,
                    f'name={parsed_sender_name}, domain={sender_domain}', verify_sender)
                break
        else:
            if any(role in display_name for role in ROLE_NAMES) and sender_domain.split('.')[0] in {'gmail', 'yahoo', 'outlook', 'hotmail'}:
                signals['header_displayname_impersonation'] = _signal(
                    'header_displayname_impersonation', ThreatSeverity.medium, 'Role-name impersonation',
                    'An organizational role is presented from a consumer mailbox domain.', 20,
                    f'name={parsed_sender_name}, domain={sender_domain}', verify_sender)

    if not message_id:
        signals['header_missing_message_id'] = _signal(
            'header_missing_message_id', ThreatSeverity.low, 'Missing Message-ID',
            'The message lacks the identifier normally created by a mail system.', 5, 'Message-ID header absent',
            'Use this only as supporting evidence and verify other message details.')
    elif not MESSAGE_ID_PATTERN.fullmatch(message_id.strip()):
        signals['header_invalid_message_id'] = _signal(
            'header_invalid_message_id', ThreatSeverity.medium, 'Malformed Message-ID',
            'The Message-ID does not follow the expected <local@domain> structure.', 12, message_id[:200],
            'Treat the malformed identifier as supporting evidence and verify the sender.')

    auth = headers.get('authentication-results')
    has_transport_headers = any(name in headers for name in ('received', 'return-path', 'dkim-signature', 'received-spf'))
    if not auth:
        if has_transport_headers:
            signals['header_missing_authentication'] = _signal(
                'header_missing_authentication', ThreatSeverity.low, 'Missing authentication results',
                'No SPF, DKIM, or DMARC result is available in the supplied message headers.', 5,
                'Authentication-Results header absent',
                'Do not treat absence alone as malicious; check the original message in the receiving mailbox.')
    else:
        for mechanism, label in (('spf', 'SPF'), ('dkim', 'DKIM'), ('dmarc', 'DMARC')):
            result = _auth_result(auth, mechanism)
            if result in {'fail', 'hardfail'}:
                signals[f'header_{mechanism}_fail'] = _signal(
                    f'header_{mechanism}_fail', ThreatSeverity.high, f'{label} authentication failed',
                    f'The receiving mail system reports that {label} validation failed.', 24,
                    f'{mechanism}={result}', 'Do not trust the sender identity until verified through another channel.')
            elif result in {'softfail', 'neutral', 'temperror', 'permerror'}:
                signals[f'header_{mechanism}_inconclusive'] = _signal(
                    f'header_{mechanism}_inconclusive', ThreatSeverity.medium, f'{label} authentication inconclusive',
                    f'The {label} result does not provide a clean authentication pass.', 10,
                    f'{mechanism}={result}', 'Use this as supporting evidence and verify the sender independently.')

    actual_return_path = return_path or headers.get('return-path')
    return_domain = _domain(actual_return_path)
    if actual_return_path and not return_domain and actual_return_path.strip() != '<>':
        signals['header_invalid_returnpath'] = _signal(
            'header_invalid_returnpath', ThreatSeverity.medium, 'Malformed Return-Path',
            'The envelope return address cannot be parsed as a mailbox.', 12, actual_return_path[:200], verify_sender)
    elif return_domain and sender_domain and return_domain != sender_domain:
        signals['header_returnpath_mismatch'] = _signal(
            'header_returnpath_mismatch', ThreatSeverity.medium, 'Return-Path domain mismatch',
            'Delivery failures are routed to a domain different from the visible From address.', 16,
            f'from={sender_domain}, return_path={return_domain}',
            'Verify that the return-path domain belongs to a legitimate sending service for the sender.')

    return list(signals.values())
