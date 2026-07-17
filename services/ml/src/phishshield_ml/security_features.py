"""Deterministic text-derived security indicators for the academic baseline."""

from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin


URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+|\bwww\.[^\s<>\"']+")
HEADER_RE = re.compile(r"(?im)^(from|reply-to):\s*(.+)$")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b")
HREF_RE = re.compile(r"(?is)<a\b[^>]*href=[\"']?([^\"'\s>]+)[^>]*>(.*?)</a>")
TAG_RE = re.compile(r"(?is)<[^>]+>")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "support", "country", "gq",
    "tk", "ml", "cf", "ga", "buzz", "rest", "cam", "monster", "quest",
}
URGENCY_TERMS = (
    "urgent", "immediately", "within 24", "within 48", "act now", "expires",
    "suspended", "suspension", "final warning", "limited time", "today",
    "as soon as possible", "without delay", "locked", "disabled",
)
CREDENTIAL_TERMS = (
    "password", "credentials", "sign in", "signin", "log in", "login", "verify your account",
    "confirm your account", "recovery code", "one-time code", "otp", "mfa", "authentication code",
    "security code", "banking details", "social security", "payment details",
)
RISKY_ATTACHMENT_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "ps1",
    "hta", "lnk", "iso", "img", "jar", "msi", "docm", "xlsm", "zip", "rar",
}


FEATURE_NAMES = np.asarray([
    "url_count",
    "shortened_url",
    "punycode_domain",
    "suspicious_tld",
    "ip_literal_url",
    "obfuscated_url",
    "sender_reply_to_mismatch",
    "sender_link_domain_mismatch",
    "html_link_text_mismatch",
    "html_present",
    "urgency_score",
    "credential_language_score",
    "attachment_indicator",
    "risky_attachment_indicator",
], dtype=object)


def _domain(value: str) -> str:
    address = parseaddr(value)[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def _host(value: str) -> str:
    normalized = re.sub(r"(?i)^hxxp", "http", value.strip().rstrip(".,);]"))
    if normalized.lower().startswith("www."):
        normalized = "http://" + normalized
    try:
        return (urlparse(normalized).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def _registrable_approx(domain: str) -> str:
    parts = [part for part in domain.lower().split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def extract_security_indicators(text: str) -> np.ndarray:
    lower = text.lower()
    urls = URL_RE.findall(text)
    hosts = [host for host in (_host(url) for url in urls) if host]
    headers = {name.lower(): value for name, value in HEADER_RE.findall(text)}
    sender = _domain(headers.get("from", ""))
    reply_to = _domain(headers.get("reply-to", ""))
    sender_base = _registrable_approx(sender)
    link_bases = {_registrable_approx(host) for host in hosts}

    mismatched_html_link = False
    for href, visible_html in HREF_RE.findall(text):
        href_host = _host(href)
        visible_domains = DOMAIN_RE.findall(TAG_RE.sub(" ", visible_html))
        if href_host and visible_domains and all(
            _registrable_approx(domain) != _registrable_approx(href_host) for domain in visible_domains
        ):
            mismatched_html_link = True
            break

    attachment_names = re.findall(
        r"(?i)(?:filename\s*=\s*[\"']?|attachment\s*:\s*)([^\s\"';]+)", text
    )
    attachment_extensions = {
        name.rsplit(".", 1)[-1].lower() for name in attachment_names if "." in name
    }
    urgency_count = sum(term in lower for term in URGENCY_TERMS)
    credential_count = sum(term in lower for term in CREDENTIAL_TERMS)
    suspicious_tld = any(host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS for host in hosts if "." in host)
    ip_literal = any(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) for host in hosts)

    return np.asarray([
        min(len(urls), 5) / 5.0,
        float(any(_registrable_approx(host) in SHORTENERS for host in hosts)),
        float(any("xn--" in host for host in hosts)),
        float(suspicious_tld),
        float(ip_literal),
        float("hxxp" in lower or "[.]" in lower),
        float(bool(sender and reply_to and sender_base != _registrable_approx(reply_to))),
        float(bool(sender and link_bases and sender_base not in link_bases)),
        float(mismatched_html_link),
        float("<html" in lower or "<a " in lower or "text/html" in lower),
        min(urgency_count, 5) / 5.0,
        min(credential_count, 5) / 5.0,
        min(len(attachment_names), 3) / 3.0,
        float(bool(attachment_extensions & RISKY_ATTACHMENT_EXTENSIONS)),
    ], dtype=float)


class SecurityIndicatorTransformer(BaseEstimator, TransformerMixin):
    """Convert message text to bounded, explainable security indicators."""

    def fit(self, X, y=None):  # noqa: N803 - sklearn API
        return self

    def transform(self, X):  # noqa: N803 - sklearn API
        rows = [extract_security_indicators(str(text)) for text in X]
        return csr_matrix(np.vstack(rows) if rows else np.empty((0, len(FEATURE_NAMES))))

    def get_feature_names_out(self, input_features=None):
        return FEATURE_NAMES.copy()

