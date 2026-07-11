"""URL analyzer for deterministic, explainable signals."""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable
from urllib.parse import urlparse

from app.schemas.analysis import ThreatSignal, ThreatSeverity

logger = logging.getLogger(__name__)

# Known shorteners (conservative list)
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly'
}

SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'secure', 'update', 'account', 'password', 'billing', 'wallet', 'auth'
}

EXCESSIVE_SUBDOMAIN_COUNT = 4  # e.g., a.b.c.d.example.com -> parts > 4 considered excessive
SUSPICIOUS_URL_LENGTH = 200


def _hostname_from_url(url: str) -> str | None:
    try:
        p = urlparse(url)
        return p.hostname
    except Exception:
        return None


def analyze_urls(urls: Iterable[str], sender_domain: str | None = None) -> list[ThreatSignal]:
    signals: dict[str, ThreatSignal] = {}

    for raw in set(urls or []):
        try:
            p = urlparse(raw)
        except Exception:
            signals['url_malformed'] = ThreatSignal(
                code='url_malformed',
                category='url',
                severity=ThreatSeverity.low,
                title='Malformed URL',
                description='URL could not be parsed safely',
                score=10,
                evidence=raw[:200]
            )
            continue

        scheme = (p.scheme or '').lower()
        hostname = p.hostname
        port = p.port

        # HTTP instead of HTTPS
        if scheme == 'http':
            signals.setdefault('url_insecure_scheme', ThreatSignal(
                code='url_insecure_scheme',
                category='url',
                severity=ThreatSeverity.low,
                title='Insecure URL (HTTP)',
                description='URL uses HTTP instead of HTTPS',
                score=10,
                evidence=raw[:200]
            ))

        # Shortener
        if hostname and hostname.lower() in SHORTENERS:
            signals.setdefault('url_shortener', ThreatSignal(
                code='url_shortener',
                category='url',
                severity=ThreatSeverity.medium,
                title='URL shortener detected',
                description='Shortened URL may obscure destination',
                score=30,
                evidence=hostname
            ))

        # IP-address host
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                signals.setdefault('url_ip_host', ThreatSignal(
                    code='url_ip_host',
                    category='url',
                    severity=ThreatSeverity.medium,
                    title='IP address used in URL host',
                    description='Numeric IP host may indicate malicious redirect',
                    score=40,
                    evidence=hostname
                ))
            except Exception:
                pass

        # Punycode
        if hostname and 'xn--' in hostname:
            signals.setdefault('url_punycode', ThreatSignal(
                code='url_punycode',
                category='url',
                severity=ThreatSeverity.medium,
                title='Punycode domain detected',
                description='Punycode (IDNA) may be used for homograph attacks',
                score=40,
                evidence=hostname
            ))

        # Excessive subdomains
        if hostname:
            parts = hostname.split('.')
            if len(parts) > EXCESSIVE_SUBDOMAIN_COUNT:
                signals.setdefault('url_excessive_subdomains', ThreatSignal(
                    code='url_excessive_subdomains',
                    category='url',
                    severity=ThreatSeverity.low,
                    title='Excessive subdomain levels',
                    description='Many subdomain components may hide the registrable domain',
                    score=15,
                    evidence=f'parts={len(parts)}'
                ))

        # Suspicious URL length
        if len(raw) > SUSPICIOUS_URL_LENGTH:
            signals.setdefault('url_long', ThreatSignal(
                code='url_long',
                category='url',
                severity=ThreatSeverity.low,
                title='Suspicious URL length',
                description='Very long URL might hide malicious content',
                score=10,
                evidence=f'len={len(raw)}'
            ))

        # Suspicious keywords
        path_query = (p.path or '') + (p.query or '')
        if any(k in path_query.lower() for k in SUSPICIOUS_KEYWORDS):
            signals.setdefault('url_suspicious_keyword', ThreatSignal(
                code='url_suspicious_keyword',
                category='url',
                severity=ThreatSeverity.medium,
                title='Suspicious keyword in URL',
                description='URL path or query contains login/verify keywords',
                score=30,
                evidence=raw[:200]
            ))

        # User-info abuse
        if '@' in p.netloc:
            signals.setdefault('url_userinfo', ThreatSignal(
                code='url_userinfo',
                category='url',
                severity=ThreatSeverity.medium,
                title='User-info or @ in URL',
                description='User-info in URL can obfuscate real host',
                score=40,
                evidence=raw[:200]
            ))

        # Suspicious port
        if port and port not in (80, 443):
            signals.setdefault('url_suspicious_port', ThreatSignal(
                code='url_suspicious_port',
                category='url',
                severity=ThreatSeverity.low,
                title='Non-standard port in URL',
                description='Explicit non-standard port present',
                score=10,
                evidence=str(port)
            ))

        # Sender-domain mismatch (conservative): compare last two labels
        if sender_domain and hostname:
            try:
                s_parts = sender_domain.lower().split('.')
                h_parts = hostname.lower().split('.')
                if len(s_parts) >= 2 and len(h_parts) >= 2:
                    s_base = '.'.join(s_parts[-2:])
                    h_base = '.'.join(h_parts[-2:])
                    if s_base != h_base:
                        signals.setdefault('url_sender_domain_mismatch', ThreatSignal(
                            code='url_sender_domain_mismatch',
                            category='url',
                            severity=ThreatSeverity.medium,
                            title='Sender domain and URL host mismatch',
                            description='URL hostname does not match sender domain',
                            score=30,
                            evidence=f'sender={sender_domain}, url={hostname}'
                        ))
            except Exception:
                pass

    return list(signals.values())
