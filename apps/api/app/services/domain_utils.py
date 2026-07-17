"""Offline registrable-domain helpers backed by the bundled Public Suffix List."""

from __future__ import annotations

import ipaddress

import tldextract


# Never fetch suffix data while analyzing an email. tldextract ships a PSL snapshot;
# private suffixes are included because hosted platforms are security boundaries too.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def normalize_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    normalized = hostname.strip().lower().rstrip('.')
    if not normalized:
        return None
    try:
        return normalized.encode('idna').decode('ascii')
    except UnicodeError:
        return normalized


def registrable_domain(hostname: str | None) -> str | None:
    """Return eTLD+1 without network access, preserving IP literals as-is."""
    normalized = normalize_hostname(hostname)
    if not normalized:
        return None
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass
    extracted = _EXTRACT(normalized)
    return extracted.top_domain_under_public_suffix or normalized


def domains_align(left: str | None, right: str | None) -> bool:
    left_domain = registrable_domain(left)
    right_domain = registrable_domain(right)
    return bool(left_domain and right_domain and left_domain == right_domain)
