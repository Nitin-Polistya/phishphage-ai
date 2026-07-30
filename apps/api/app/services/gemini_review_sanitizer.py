"""Privacy-first, deterministic sanitizer for Gemini review evidence.

This module intentionally has no network, filesystem, or provider behavior.
It produces a small canonical payload so the consent hash binds exactly what
the reviewer saw immediately before submission.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urlsplit

from app.core.settings import Settings, get_settings
from app.schemas.email import ParsedEmail
from app.schemas.gemini_review import SanitizedReviewInput, SanitizedReviewPayload


EMAIL_RE = re.compile(r'(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])')
URL_RE = re.compile(r'(?i)\b(?:https?|ftp|javascript|data|file|blob|chrome):[^\s<>"\']+')
PHONE_RE = re.compile(r'(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)')
BASE64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])')
LONG_TOKEN_RE = re.compile(r'(?i)\b(?:token|secret|api[_ -]?key|authorization|bearer|cookie|session)[ :=_-]*[^\s,;]{8,}')
PATH_RE = re.compile(r'(?i)(?:[A-Za-z]:\\|\\\\|/Users/|/home/|/tmp/|/var/|file://)[^\s]+')
BIDI_CHARS = {chr(value) for value in range(0x202A, 0x202F)} | {chr(value) for value in range(0x2066, 0x206A)}
CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
WHITESPACE_RE = re.compile(r'[ \t\r\n]+')
REPEATED_RE = re.compile(r'(.)\1{4,}')
HTML_MARKUP_RE = re.compile(r'(?is)<!--.*?-->|<script\b[^>]*>.*?</script\s*>|<style\b[^>]*>.*?</style\s*>|<[^>]{1,500}>')
PRIVATE_IP_RE = re.compile(r'(?<![\w.])(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d{1,3}(?:\.\d{1,3})?(?![\w.])')
TWO_PART_SUFFIXES = {'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'co.in', 'co.jp', 'com.br', 'co.nz'}


class SanitizationError(ValueError):
    """Raised when evidence cannot be reduced to the review contract."""


def registrable_domain(value: str | None) -> str:
    if not value:
        return ''
    candidate = value.strip().lower().rstrip('.')
    if '@' in candidate:
        candidate = candidate.rsplit('@', 1)[-1]
    candidate = candidate.strip('[]')
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        return '[ip-redacted]' if not address.is_loopback else '[internal-ip-redacted]'
    if not re.fullmatch(r'[a-z0-9.-]{1,253}', candidate) or '..' in candidate:
        return ''
    parts = [part for part in candidate.split('.') if part]
    if len(parts) < 2:
        return candidate
    suffix = '.'.join(parts[-2:])
    return '.'.join(parts[-3:]) if suffix in TWO_PART_SUFFIXES and len(parts) >= 3 else suffix


def _clean_unicode(value: str) -> str:
    value = html.unescape(value or '')
    value = ''.join('\ufffd' if char in BIDI_CHARS else char for char in value)
    value = CONTROL_RE.sub(' ', value)
    return value


class _VisibleTextParser(HTMLParser):
    _ignored_tags = {'script', 'style', 'template', 'svg', 'object', 'embed', 'iframe', 'form', 'noscript', 'head'}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored = 0
        self._ignored_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_map = {key.lower(): (value or '').lower() for key, value in attrs}
        hidden = 'display:none' in attrs_map.get('style', '').replace(' ', '') or attrs_map.get('hidden') == ''
        if tag in self._ignored_tags or hidden:
            self._ignored += 1
            self._ignored_stack.append(tag)
        if tag in {'br', 'p', 'div', 'li', 'tr', 'h1', 'h2', 'h3'} and not self._ignored:
            self.parts.append('\n')

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._ignored_stack:
            for index in range(len(self._ignored_stack) - 1, -1, -1):
                if self._ignored_stack[index] == tag:
                    self._ignored_stack.pop(index)
                    self._ignored = max(0, self._ignored - 1)
                    break
        if tag in {'div', 'p', 'li', 'tr'} and not self._ignored:
            self.parts.append('\n')

    def handle_data(self, data: str) -> None:
        if not self._ignored:
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        return


def visible_html_text(value: str | None) -> str:
    if not value:
        return ''
    parser = _VisibleTextParser()
    try:
        parser.feed(value[:100_000])
        parser.close()
    except Exception:
        return ''
    return _sanitize_text(' '.join(parser.parts))


def _is_reserved_address(address: str) -> bool:
    return bool(re.search(r'(?i)@(?:example\.com|example\.org|example\.net|invalid|test)$', address))


def _sanitize_text(value: str | None, max_chars: int | None = None) -> str:
    cleaned = _clean_unicode(value or '')
    cleaned = HTML_MARKUP_RE.sub(' ', cleaned)
    cleaned = URL_RE.sub('[URL removed]', cleaned)
    cleaned = BASE64_RE.sub('[encoded content removed]', cleaned)
    cleaned = LONG_TOKEN_RE.sub('[credential-like value removed]', cleaned)
    cleaned = PATH_RE.sub('[local path removed]', cleaned)
    cleaned = PRIVATE_IP_RE.sub('[internal IP removed]', cleaned)
    cleaned = PHONE_RE.sub('[phone number removed]', cleaned)

    def redact_email(match: re.Match[str]) -> str:
        return match.group(0) if _is_reserved_address(match.group(0)) else '[email address removed]'

    cleaned = EMAIL_RE.sub(redact_email, cleaned)
    cleaned = REPEATED_RE.sub(lambda match: match.group(1) * 4, cleaned)
    cleaned = WHITESPACE_RE.sub(' ', cleaned).strip()
    if max_chars is not None:
        cleaned = cleaned[:max_chars].rstrip()
    return cleaned


def _safe_domain_list(values: Iterable[str], max_items: int = 30) -> list[str]:
    result: list[str] = []
    for value in values:
        domain = registrable_domain(value)
        if domain and domain not in result:
            result.append(domain)
        if len(result) >= max_items:
            break
    return result


def _url_metadata(values: Iterable[str]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    flags: list[str] = []
    for raw in values:
        raw = _clean_unicode(raw).strip().strip('.,;')
        try:
            parsed = urlsplit(raw)
        except ValueError:
            continue
        scheme = parsed.scheme.lower()
        if scheme not in {'http', 'https'}:
            flags.append(f'blocked_scheme:{scheme or "unknown"}')
            continue
        domain = registrable_domain(parsed.hostname)
        if domain:
            domains.append(domain)
        if parsed.query:
            flags.append('query_present_removed')
        if parsed.fragment:
            flags.append('fragment_present_removed')
        if parsed.username or parsed.password:
            flags.append('userinfo_present')
        if parsed.hostname and parsed.hostname.startswith('xn--'):
            flags.append('punycode_domain')
        if len(parsed.path) > 80:
            flags.append('long_path')
    return _safe_domain_list(domains), sorted(set(flags))


def _canonical_hash(data: dict[str, object]) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def sanitize_review_input(
    evidence: SanitizedReviewInput,
    *,
    model_name: str,
    prompt_version: str,
    settings: Settings | None = None,
) -> SanitizedReviewPayload:
    settings = settings or get_settings()
    if not model_name.strip():
        raise SanitizationError('A configured model name is required before preview.')
    subject = _sanitize_text(evidence.subject, settings.gemini_sanitized_subject_max_chars)
    body_source = visible_html_text(evidence.body_excerpt) if '<' in evidence.body_excerpt and '>' in evidence.body_excerpt else evidence.body_excerpt
    body = _sanitize_text(body_source, settings.gemini_sanitized_body_max_chars)
    html_text = _sanitize_text(visible_html_text(evidence.visible_html_text), settings.gemini_sanitized_body_max_chars)
    domains = _safe_domain_list([evidence.sender_domain or '', evidence.reply_to_domain or '', evidence.return_path_domain or ''])
    url_domains, url_flags = _url_metadata(evidence.url_domains)
    auth = [_sanitize_text(item, 240) for item in evidence.authentication_summary[:10] if _sanitize_text(item, 240)]
    parser_evidence = [_sanitize_text(item, 300) for item in evidence.parser_evidence[:30] if _sanitize_text(item, 300)]
    payload_data: dict[str, object] = {
        'sample_id': evidence.sample_id,
        'subject': subject,
        'display_name': _sanitize_text(evidence.display_name, 160),
        'sender_domain': registrable_domain(evidence.sender_domain),
        'reply_to_domain': registrable_domain(evidence.reply_to_domain),
        'return_path_domain': registrable_domain(evidence.return_path_domain),
        'authentication_summary': auth,
        'body_excerpt': body,
        'visible_html_text': html_text,
        'url_domains': _safe_domain_list([*url_domains, *evidence.url_domains]),
        'url_structural_flags': sorted(set([*url_flags, *[_sanitize_text(item, 120) for item in evidence.url_structural_flags]])),
        'attachment_extension': _sanitize_text(evidence.attachment_extension, 32).lower(),
        'attachment_mime': _sanitize_text(evidence.attachment_mime, 160).lower(),
        'parser_evidence': parser_evidence,
        'candidate_campaign_category': _sanitize_text(evidence.candidate_campaign_category, 120),
        'model_name': model_name.strip(),
        'prompt_version': prompt_version.strip(),
    }
    payload_hash = _canonical_hash(payload_data)
    payload = SanitizedReviewPayload(**payload_data, sanitized_payload_hash=payload_hash)
    serialized_size = len(json.dumps(payload.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode('utf-8'))
    if serialized_size > settings.gemini_sanitized_payload_max_bytes:
        raise SanitizationError('Sanitized payload exceeds the configured byte limit.')
    return payload


def sanitize_parsed_email(
    sample_id: str,
    parsed: ParsedEmail,
    *,
    model_name: str,
    prompt_version: str,
    settings: Settings | None = None,
    candidate_campaign_category: str | None = None,
) -> SanitizedReviewPayload:
    """Convert local parser output without serializing raw headers or addresses."""
    sender_domain = parsed.sender.address.rsplit('@', 1)[-1] if parsed.sender else ''
    reply_domain = parsed.reply_to.address.rsplit('@', 1)[-1] if parsed.reply_to else ''
    auth: list[str] = []
    for header_name in ('authentication-results', 'received-spf', 'arc-authentication-results'):
        if header_name in {key.lower() for key in parsed.headers}:
            value = parsed.headers.get(header_name) or parsed.headers.get(header_name.title(), '')
            statuses = re.findall(r'(?i)\b(?:spf|dkim|dmarc|arc)\s*[=:]\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', value)
            auth.extend(f'{header_name}:{status.lower()}' for status in statuses[:4])
    urls = [item.url for item in parsed.url_evidence] if parsed.url_evidence else parsed.extracted_urls
    return sanitize_review_input(
        SanitizedReviewInput(
            sample_id=sample_id,
            subject=parsed.subject,
            display_name=parsed.sender.name if parsed.sender else None,
            sender_domain=sender_domain,
            reply_to_domain=reply_domain,
            authentication_summary=auth,
            body_excerpt=parsed.body_text,
            visible_html_text=parsed.body_visible_text,
            url_domains=urls,
            url_structural_flags=[],
            attachment_extension=parsed.attachments[0].extension if parsed.attachments else None,
            attachment_mime=parsed.attachments[0].content_type if parsed.attachments else None,
            parser_evidence=[f'url_count:{parsed.actual_url_count}', f'attachment_count:{len(parsed.attachments)}'],
            candidate_campaign_category=candidate_campaign_category,
        ),
        model_name=model_name,
        prompt_version=prompt_version,
        settings=settings,
    )


def payload_bytes(payload: SanitizedReviewPayload) -> int:
    return len(json.dumps(payload.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode('utf-8'))


def payload_hash_matches(payload: SanitizedReviewPayload) -> bool:
    data = payload.model_dump(mode='json')
    supplied = data.pop('sanitized_payload_hash')
    return supplied == _canonical_hash(data)


def validate_payload_before_submission(payload: SanitizedReviewPayload, settings: Settings | None = None) -> None:
    """Re-check the canonical preview immediately before provider submission."""
    settings = settings or get_settings()
    if not payload_hash_matches(payload):
        raise SanitizationError('Sanitized payload hash does not match its contents.')
    if payload.model_name != payload.model_name.strip() or payload.prompt_version != payload.prompt_version.strip():
        raise SanitizationError('Sanitized payload binding is invalid.')
    if payload_bytes(payload) > settings.gemini_sanitized_payload_max_bytes:
        raise SanitizationError('Sanitized payload exceeds the configured byte limit.')
    if len(payload.subject) > settings.gemini_sanitized_subject_max_chars or len(payload.body_excerpt) > settings.gemini_sanitized_body_max_chars:
        raise SanitizationError('Sanitized subject or body exceeds the configured limit.')
    forbidden = ('<script', '<style', '<iframe', '<form', 'data:', 'javascript:', 'file:', 'ftp:', 'blob:', 'chrome:')
    text_fields = [payload.subject, payload.display_name, payload.body_excerpt, payload.visible_html_text, *payload.authentication_summary, *payload.parser_evidence]
    if any(any(marker in value.casefold() for marker in forbidden) or '\r' in value or '\n' in value for value in text_fields):
        raise SanitizationError('Sanitized payload contains forbidden content.')
    for domain in [payload.sender_domain, payload.reply_to_domain, payload.return_path_domain, *payload.url_domains]:
        if domain and domain not in {'[ip-redacted]', '[internal-ip-redacted]'} and registrable_domain(domain) != domain:
            raise SanitizationError('Only registrable domains may be submitted.')
