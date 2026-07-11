"""Header analyzer: deterministic header-based signals."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from app.schemas.analysis import ThreatSignal, ThreatSeverity

logger = logging.getLogger(__name__)

IMPERSONATION_ORGS = ['microsoft', 'google', 'paypal', 'bank', 'security team', 'it support']


def _get_domain(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    # naive extraction: take part after @ if present
    if '@' in addr:
        return addr.split('@')[-1].lower()
    return None


def analyze_headers(parsed_headers: Dict[str, str], parsed_sender_address: Optional[str], parsed_sender_name: Optional[str], return_path: Optional[str], message_id: Optional[str]) -> list[ThreatSignal]:
    signals: dict[str, ThreatSignal] = {}

    # Missing sender
    if not parsed_sender_address:
        signals['missing_sender'] = ThreatSignal(
            code='header_missing_sender',
            category='header',
            severity=ThreatSeverity.high,
            title='Missing sender address',
            description='Message does not contain a parsable sender address',
            score=60,
            evidence=None
        )
        return list(signals.values())

    # Malformed sender address (simple check)
    if '@' not in parsed_sender_address:
        signals['malformed_sender'] = ThreatSignal(
            code='header_malformed_sender',
            category='header',
            severity=ThreatSeverity.medium,
            title='Malformed sender address',
            description='Sender address does not contain @',
            score=30,
            evidence=parsed_sender_address
        )

    # Reply-To mismatch
    reply_to = parsed_headers.get('reply-to')
    if reply_to:
        r_domain = _get_domain(reply_to)
        s_domain = _get_domain(parsed_sender_address)
        if r_domain and s_domain and r_domain != s_domain:
            signals.setdefault('replyto_mismatch', ThreatSignal(
                code='header_replyto_mismatch',
                category='header',
                severity=ThreatSeverity.medium,
                title='Reply-To domain mismatch',
                description='Reply-To domain differs from sender domain',
                score=30,
                evidence=f'reply_to={r_domain}, sender={s_domain}'
            ))

    # Display-name impersonation
    if parsed_sender_name:
        lc = parsed_sender_name.lower()
        for org in IMPERSONATION_ORGS:
            if org in lc:
                s_domain = _get_domain(parsed_sender_address)
                if s_domain and org not in s_domain:
                    signals.setdefault('displayname_impersonation', ThreatSignal(
                        code='header_displayname_impersonation',
                        category='header',
                        severity=ThreatSeverity.medium,
                        title='Display name impersonation',
                        description='Sender display name claims organization but domain does not match',
                        score=30,
                        evidence=parsed_sender_name
                    ))
                break

    # Missing Message-ID
    if not message_id:
        signals.setdefault('missing_message_id', ThreatSignal(
            code='header_missing_message_id',
            category='header',
            severity=ThreatSeverity.low,
            title='Missing Message-ID',
            description='Message-ID header is missing',
            score=10,
            evidence=None
        ))

    # Authentication-Results checks
    auth = parsed_headers.get('authentication-results') or parsed_headers.get('authentication_results')
    if auth:
        la = auth.lower()
        if 'spf=fail' in la or 'spf: fail' in la:
            signals.setdefault('auth_spf_fail', ThreatSignal(
                code='header_spf_fail',
                category='header',
                severity=ThreatSeverity.high,
                title='SPF failure reported',
                description='Authentication-Results header indicates SPF failure',
                score=60,
                evidence=None
            ))
        if 'dkim=fail' in la or 'dkim: fail' in la:
            signals.setdefault('auth_dkim_fail', ThreatSignal(
                code='header_dkim_fail',
                category='header',
                severity=ThreatSeverity.high,
                title='DKIM failure reported',
                description='Authentication-Results header indicates DKIM failure',
                score=60,
                evidence=None
            ))
        if 'dmarc=fail' in la or 'dmarc: fail' in la:
            signals.setdefault('auth_dmarc_fail', ThreatSignal(
                code='header_dmarc_fail',
                category='header',
                severity=ThreatSeverity.high,
                title='DMARC failure reported',
                description='Authentication-Results header indicates DMARC failure',
                score=60,
                evidence=None
            ))

    # From and Return-Path mismatch
    if return_path:
        rp_domain = _get_domain(return_path)
        from_domain = _get_domain(parsed_sender_address)
        if rp_domain and from_domain and rp_domain != from_domain:
            signals.setdefault('returnpath_mismatch', ThreatSignal(
                code='header_returnpath_mismatch',
                category='header',
                severity=ThreatSeverity.medium,
                title='Return-Path mismatch',
                description='Return-Path domain differs from From domain',
                score=30,
                evidence=f'returnpath={rp_domain}, from={from_domain}'
            ))

    return list(signals.values())
