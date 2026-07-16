"""URL analyzer for deterministic, explainable signals."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Iterable
from urllib.parse import unquote, urlparse

from app.schemas.analysis import ThreatSignal, ThreatSeverity

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'lnkd.in', 's.id', 'qrco.de',
}

SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'secure', 'update', 'account', 'password', 'billing', 'wallet', 'auth'
}

EXCESSIVE_SUBDOMAIN_COUNT = 4  # e.g., a.b.c.d.example.com -> parts > 4 considered excessive
SUSPICIOUS_URL_LENGTH = 200
SUSPICIOUS_TLDS = {
    'click', 'country', 'download', 'gq', 'info', 'link', 'live', 'loan', 'men', 'mom',
    'party', 'rest', 'review', 'science', 'stream', 'support', 'top', 'win', 'work', 'xyz',
}
PROTECTED_BRANDS = {
    'amazon', 'apple', 'coinbase', 'dhl', 'dropbox', 'facebook', 'fedex', 'google',
    'instagram', 'linkedin', 'mastercard', 'microsoft', 'netflix', 'office365', 'outlook',
    'paypal', 'stripe', 'ups', 'visa', 'whatsapp', 'yahoo',
}
OFFICIAL_DOMAINS = {
    'amazon': {'amazon.com'}, 'apple': {'apple.com'}, 'coinbase': {'coinbase.com'},
    'dhl': {'dhl.com'}, 'dropbox': {'dropbox.com'}, 'facebook': {'facebook.com'},
    'fedex': {'fedex.com'}, 'google': {'google.com'}, 'instagram': {'instagram.com'},
    'linkedin': {'linkedin.com'}, 'microsoft': {'microsoft.com'}, 'netflix': {'netflix.com'},
    'office365': {'microsoft.com', 'office.com'}, 'outlook': {'outlook.com', 'microsoft.com'},
    'paypal': {'paypal.com'}, 'stripe': {'stripe.com'}, 'ups': {'ups.com'},
    'visa': {'visa.com'}, 'whatsapp': {'whatsapp.com'}, 'yahoo': {'yahoo.com'},
}
ENCODING_TRICK = re.compile(r'%(?:25)?(?:2f|3a|40|5c|2e)', re.IGNORECASE)


def _signal(code: str, severity: ThreatSeverity, title: str, description: str, score: int,
            evidence: str, recommendation: str = 'Open the destination only through the organization\'s official website.') -> ThreatSignal:
    return ThreatSignal(code=code, category='url', severity=severity, title=title,
                        description=description, score=score, evidence=evidence, recommendation=recommendation)


def _base_domain(hostname: str) -> str:
    parts = hostname.rstrip('.').lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def _skeleton(value: str) -> str:
    substitutions = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't'})
    return re.sub(r'[^a-z0-9]', '', value.lower()).translate(substitutions)


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) <= 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    for index in range(len(long)):
        if long[:index] + long[index + 1:] == short:
            return True
    return False


def _mixed_scripts(hostname: str) -> bool:
    scripts = set()
    for char in hostname:
        if char.isalpha() and ord(char) > 127:
            name = unicodedata.name(char, '')
            scripts.add(name.split(' ', 1)[0])
        elif char.isascii() and char.isalpha():
            scripts.add('LATIN')
    return len(scripts) > 1


def _hostname_from_url(url: str) -> str | None:
    try:
        p = urlparse(url)
        return p.hostname
    except Exception:
        return None


def analyze_urls(urls: Iterable[str], sender_domain: str | None = None) -> list[ThreatSignal]:
    signals: dict[str, ThreatSignal] = {}
    schemes: set[str] = set()

    for raw in set(urls or []):
        try:
            p = urlparse(raw)
        except Exception:
            signals['url_malformed'] = _signal('url_malformed', ThreatSeverity.low, 'Malformed URL',
                'The URL could not be parsed safely.', 8, raw[:200])
            continue

        scheme = (p.scheme or '').lower()
        hostname = p.hostname
        try:
            port = p.port
        except ValueError:
            port = None
            signals.setdefault('url_malformed_port', _signal('url_malformed_port', ThreatSeverity.medium,
                'Malformed URL port', 'The URL contains an invalid or deliberately confusing port.', 18, raw[:200]))
        if scheme in {'http', 'https'}:
            schemes.add(scheme)

        # HTTP instead of HTTPS
        if scheme == 'http':
            signals.setdefault('url_insecure_scheme', _signal('url_insecure_scheme', ThreatSeverity.low,
                'Insecure URL (HTTP)', 'The link sends data without HTTPS transport protection.', 8, raw[:200]))

        # Shortener
        if hostname and hostname.lower() in SHORTENERS:
            signals.setdefault('url_shortener', _signal('url_shortener', ThreatSeverity.medium,
                'Shortened URL hides destination', 'A link-shortening service conceals the final destination.', 18, hostname))

        # IP-address host
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                signals.setdefault('url_ip_host', _signal('url_ip_host', ThreatSeverity.high,
                    'IP address used as link host', 'The link uses a numeric host instead of an identifiable domain.', 28, hostname))
            except Exception:
                pass

        # Punycode
        if hostname and 'xn--' in hostname:
            signals.setdefault('url_punycode', _signal('url_punycode', ThreatSeverity.high,
                'Punycode domain may mimic another site', 'The hostname uses IDNA encoding, a technique used in homograph attacks.', 30, hostname))
        elif hostname and _mixed_scripts(hostname):
            signals.setdefault('url_homograph', _signal('url_homograph', ThreatSeverity.high,
                'Mixed-script hostname', 'The hostname mixes writing systems and may visually imitate a trusted domain.', 32, hostname))

        if hostname:
            base = _base_domain(hostname)
            label = base.split('.')[0]
            candidate = _skeleton(label)
            for brand in PROTECTED_BRANDS:
                official = base in OFFICIAL_DOMAINS.get(brand, set())
                brand_skeleton = _skeleton(brand)
                looks_like = candidate != brand_skeleton and (
                    brand_skeleton in candidate or _edit_distance_at_most_one(candidate, brand_skeleton)
                )
                if looks_like and not official:
                    signals.setdefault('url_lookalike_domain', _signal('url_lookalike_domain', ThreatSeverity.high,
                        'Look-alike domain detected', 'The domain closely resembles a commonly impersonated brand.', 34,
                        f'host={hostname}, resembles={brand}'))
                    break

            tld = hostname.rstrip('.').rsplit('.', 1)[-1].lower()
            if tld in SUSPICIOUS_TLDS:
                signals.setdefault('url_suspicious_tld', _signal('url_suspicious_tld', ThreatSeverity.medium,
                    'Higher-risk top-level domain', 'The link uses a TLD frequently abused in disposable phishing infrastructure.', 14, f'.{tld}'))

        decoded_once = unquote(raw)
        if ENCODING_TRICK.search(raw) or unquote(decoded_once) != decoded_once or raw.count('%') >= 4:
            signals.setdefault('url_encoding_trick', _signal('url_encoding_trick', ThreatSeverity.medium,
                'URL encoding obscures the destination', 'Encoded or double-encoded delimiters make the link harder to inspect.', 18, raw[:200]))

        # Excessive subdomains
        if hostname:
            parts = hostname.split('.')
            if len(parts) > EXCESSIVE_SUBDOMAIN_COUNT:
                signals.setdefault('url_excessive_subdomains', _signal('url_excessive_subdomains', ThreatSeverity.medium,
                    'Excessive subdomain levels', 'Many hostname levels can hide the true registrable domain.', 14,
                    f'host={hostname}, labels={len(parts)}'))

        # Suspicious URL length
        if len(raw) > SUSPICIOUS_URL_LENGTH:
            signals.setdefault('url_long', _signal('url_long', ThreatSeverity.low, 'Unusually long URL',
                'The link is long enough to conceal important destination details.', 6, f'length={len(raw)}'))

        # Suspicious keywords
        path_query = (p.path or '') + (p.query or '')
        if any(k in path_query.lower() for k in SUSPICIOUS_KEYWORDS):
            signals.setdefault('url_suspicious_keyword', _signal('url_suspicious_keyword', ThreatSeverity.medium,
                'Sensitive-action keyword in URL', 'The path asks for a login, verification, billing, or account action.', 14, raw[:200]))

        # User-info abuse
        if '@' in p.netloc:
            signals.setdefault('url_userinfo', _signal('url_userinfo', ThreatSeverity.high,
                'URL user-info hides the real host', 'Text before @ can make a malicious host look trusted.', 28, raw[:200]))

        # Suspicious port
        if port and port not in (80, 443):
            signals.setdefault('url_suspicious_port', _signal('url_suspicious_port', ThreatSeverity.medium,
                'Non-standard web port', 'The link explicitly uses a port other than standard HTTP or HTTPS.', 12, str(port)))

        # Sender-domain mismatch (conservative): compare last two labels
        if sender_domain and hostname:
            try:
                s_parts = sender_domain.lower().split('.')
                h_parts = hostname.lower().split('.')
                if len(s_parts) >= 2 and len(h_parts) >= 2:
                    s_base = '.'.join(s_parts[-2:])
                    h_base = '.'.join(h_parts[-2:])
                    if s_base != h_base:
                        signals.setdefault('url_sender_domain_mismatch', _signal('url_sender_domain_mismatch', ThreatSeverity.low,
                            'Link domain differs from sender', 'The destination domain is unrelated to the sender domain; this can be legitimate but needs context.', 8,
                            f'sender={sender_domain}, url={hostname}'))
            except Exception:
                pass

    if schemes == {'http', 'https'}:
        signals['url_mixed_transport'] = _signal('url_mixed_transport', ThreatSeverity.medium,
            'Mixed HTTP and HTTPS links', 'The message mixes protected and unprotected web references.', 12,
            'schemes=http,https', 'Avoid HTTP links and navigate to the trusted site directly.')

    return list(signals.values())
