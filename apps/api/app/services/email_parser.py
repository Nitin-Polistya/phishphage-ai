"""Email parsing service."""

from __future__ import annotations

import logging
import re
from email import message_from_string
from email.header import decode_header
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse, urlsplit

from app.schemas.email import (
    EmailAddress,
    EmailAttachmentMetadata,
    EmailHtmlLink,
    EmailUrlEvidence,
    ParsedEmail,
    EmailMailtoEvidence,
    UrlSourceType,
)
from app.core.logging import log_event
from app.services.domain_utils import domains_align

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 2 * 1024 * 1024
MAX_MIME_PARTS = 100
MAX_ATTACHMENTS = 25
MAX_HEADER_LINES = 200
MAX_HEADER_LINE_BYTES = 998
MAX_EXTRACTED_URLS = 200
MAX_URL_LENGTH = 2048
RAW_SOURCE_ERROR = "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from 'Show original' / 'View source'."
STANDARD_SOURCE_HEADERS = {'from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'}
URL_PATTERN = re.compile(
    r'h(?:tt|xx)ps?://[^\s<>"\'\)]+',
    re.IGNORECASE,
)
LINK_LANGUAGE_PATTERN = re.compile(
    r'\b(?:click|tap|open|follow|use|visit|review|verify|sign\s*in|log\s*in)\b[^\n]{0,80}\b(?:link|button|below|here|page|portal|account|security)\b',
    re.IGNORECASE,
)
PERSONAL_MAILBOX_DOMAINS = frozenset({'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'aol.com'})
MAILTO_ACTION_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('report', ('report', 'abuse', 'phishing', 'spam', 'user')),
    ('security', ('security', 'alert', 'verify', 'account', 'suspicious')),
    ('payment', ('payment', 'invoice', 'billing', 'refund', 'transaction')),
    ('support', ('support', 'help', 'contact', 'customer service')),
    ('unsubscribe', ('unsubscribe', 'remove me', 'opt out')),
    ('reply', ('reply', 'respond', 'answer')),
)


def normalize_defanged_indicator(value: str) -> str:
    """Normalize only for local parsing; callers keep the original safe display form."""
    normalized = re.sub(r'^hxxps://', 'https://', value, flags=re.IGNORECASE)
    normalized = re.sub(r'^hxxp://', 'http://', normalized, flags=re.IGNORECASE)
    return re.sub(r'\[\.\]|\(dot\)', '.', normalized, flags=re.IGNORECASE)


def _domain_from_indicator(value: str) -> str | None:
    try:
        candidate = normalize_defanged_indicator(value.strip())
        if not re.match(r'^(?:https?://|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/|$))', candidate, flags=re.IGNORECASE):
            return None
        if not re.match(r'^https?://', candidate, flags=re.IGNORECASE):
            candidate = f'https://{candidate}'
        return urlparse(candidate).hostname
    except Exception:
        return None


def _mailto_action_type(visible_text: str, subject: str = '') -> str:
    context = f'{visible_text} {subject}'.casefold()
    for action_type, phrases in MAILTO_ACTION_PATTERNS:
        if any(phrase in context for phrase in phrases):
            return action_type
    return 'unknown'


def parse_mailto_evidence(value: str | None, visible_text: str = '') -> EmailMailtoEvidence:
    """Parse mailto recipients without retaining full mailbox addresses."""
    raw = (value or '').strip()
    if not raw.casefold().startswith('mailto:'):
        return EmailMailtoEvidence(visible_text=visible_text[:300], malformed=True, user_actionable=False)
    parsed = urlsplit(raw)
    recipient_text = unquote(parsed.path or '').strip()
    recipients = [part.strip() for part in recipient_text.split(',') if part.strip()]
    domains: list[str] = []
    valid_recipient_count = 0
    for recipient in recipients:
        mailbox = recipient.rsplit('<', 1)[-1].strip().strip('>')
        if '@' not in mailbox:
            continue
        local, domain = mailbox.rsplit('@', 1)
        domain = domain.casefold().strip().strip('.')
        if not local.strip() or not re.fullmatch(r'[a-z0-9.-]+', domain):
            continue
        valid_recipient_count += 1
        if domain not in domains:
            domains.append(domain)
    query = parse_qs(parsed.query, keep_blank_values=True)
    subject = unquote_plus(query.get('subject', [''])[0]) if query else ''
    action_type = _mailto_action_type(visible_text, subject)
    return EmailMailtoEvidence(
        destination_domains=domains,
        recipient_count=valid_recipient_count,
        visible_text=visible_text[:300],
        action_type=action_type,
        user_actionable=valid_recipient_count > 0,
        malformed=valid_recipient_count == 0,
    )


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[EmailHtmlLink] = []
        self.url_evidence: list[EmailUrlEvidence] = []
        self.mailto_evidence: list[EmailMailtoEvidence] = []
        self.visible_text_parts: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._hidden_tags: list[str] = []

    def _add_url(self, value: str | None, source_type: UrlSourceType, user_actionable: bool = False) -> None:
        if not value:
            return
        for url in extract_urls(value):
            evidence = EmailUrlEvidence(url=url, source_type=source_type, user_actionable=user_actionable)
            if evidence not in self.url_evidence:
                self.url_evidence.append(evidence)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {key.lower(): value for key, value in attrs}
        if tag in {'script', 'style', 'head', 'title', 'noscript', 'template'}:
            self._hidden_tags.append(tag)
        for key, value in attributes.items():
            if key == 'xmlns' or key.startswith('xmlns:'):
                self._add_url(value, UrlSourceType.namespace_or_dtd)
        if tag == 'a':
            self._href = attributes.get('href')
            self._text = []
            if not (self._href or '').casefold().startswith('mailto:'):
                self._add_url(self._href, UrlSourceType.anchor_href, user_actionable=True)
        elif tag == 'form':
            self._add_url(attributes.get('action'), UrlSourceType.form_action, user_actionable=True)
        elif tag == 'img':
            source = attributes.get('src')
            width = attributes.get('width', '').strip()
            height = attributes.get('height', '').strip()
            style = (attributes.get('style') or '').lower()
            likely_pixel = (
                (bool(width or height) and width in {'', '0', '1'} and height in {'', '0', '1'})
                or 'display:none' in style or 'display: none' in style
                or bool(source and re.search(r'(?:pixel|track|open\.(?:gif|png))', source, re.IGNORECASE))
            )
            self._add_url(source, UrlSourceType.tracking_pixel if likely_pixel else UrlSourceType.image_src)
        elif tag == 'link':
            self._add_url(attributes.get('href'), UrlSourceType.css_resource)
        elif tag == 'meta':
            self._add_url(attributes.get('content'), UrlSourceType.document_metadata)
        elif tag in {'script', 'iframe', 'source'}:
            self._add_url(attributes.get('src'), UrlSourceType.document_metadata)
        self._add_url(attributes.get('style'), UrlSourceType.css_resource)

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)
        if self._hidden_tags:
            if self._hidden_tags[-1] == 'style':
                self._add_url(data, UrlSourceType.css_resource)
            return
        normalized = re.sub(r'\s+', ' ', data).strip()
        if normalized:
            self.visible_text_parts.append(normalized)
            if self._href is None:
                self._add_url(normalized, UrlSourceType.plain_text, user_actionable=True)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._hidden_tags and tag == self._hidden_tags[-1]:
            self._hidden_tags.pop()
        if tag != 'a' or self._href is None:
            return
        visible = re.sub(r'\s+', ' ', ''.join(self._text)).strip()
        if self._href.casefold().startswith('mailto:'):
            self.mailto_evidence.append(parse_mailto_evidence(self._href, visible))
        visible_domain = _domain_from_indicator(visible) if visible else None
        href_domain = _domain_from_indicator(self._href)
        self.links.append(EmailHtmlLink(
            visible_text=visible[:300], href=self._href[:1000], visible_domain=visible_domain,
            href_domain=href_domain,
            domain_mismatch=bool(visible_domain and href_domain and not domains_align(visible_domain, href_domain)),
        ))
        self._href, self._text = None, []

    def handle_decl(self, decl: str) -> None:
        self._add_url(decl, UrlSourceType.namespace_or_dtd)


def extract_html_links(html: str | None) -> list[EmailHtmlLink]:
    if not html:
        return []
    parser = _AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        log_event(logger, logging.DEBUG, 'parser.component_failed', component='html_anchors')
    return parser.links


def extract_html_semantics(html: str | None) -> tuple[list[EmailHtmlLink], list[EmailUrlEvidence], str, list[EmailMailtoEvidence]]:
    if not html:
        return [], [], '', []
    parser = _AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        log_event(logger, logging.DEBUG, 'parser.component_failed', component='html_semantics')
    visible_text = re.sub(r'\s+', ' ', ' '.join(parser.visible_text_parts)).strip()
    return parser.links, parser.url_evidence, visible_text, parser.mailto_evidence


def validate_email_input(raw_email: str) -> None:
    """Validate email input before parsing.
    
    Args:
        raw_email: Raw email content
        
    Raises:
        ValueError: If input is invalid
    """
    if not raw_email or not raw_email.strip():
        raise ValueError('Email content cannot be empty')

    if '\x00' in raw_email:
        raise ValueError('Email content contains unsupported control characters')

    if len(raw_email.encode('utf-8')) > MAX_EMAIL_SIZE_BYTES:
        raise ValueError(f'Email exceeds maximum size of {MAX_EMAIL_SIZE_BYTES} bytes')

    header_block = re.split(r'\r?\n\r?\n', raw_email, maxsplit=1)[0]
    header_lines = header_block.splitlines()
    if len(header_lines) > MAX_HEADER_LINES:
        raise ValueError('Email contains too many headers')
    if any(len(line.encode('utf-8', errors='ignore')) > MAX_HEADER_LINE_BYTES for line in header_lines):
        raise ValueError('Email contains an oversized header line')
    if any(line and not line[:1].isspace() and ':' not in line for line in header_lines):
        raise ValueError('Email contains a malformed header')


def validate_rfc822_source(raw_email: str) -> None:
    """Reject copied display text while accepting a real RFC822 header block."""
    if not raw_email or not raw_email.strip():
        raise ValueError('Email content cannot be empty')
    if '\x00' in raw_email:
        raise ValueError('Email content contains unsupported control characters')
    if len(raw_email.encode('utf-8')) > MAX_EMAIL_SIZE_BYTES:
        raise ValueError(f'Email exceeds maximum size of {MAX_EMAIL_SIZE_BYTES} bytes')
    header_block = re.split(r'\r?\n\r?\n', raw_email, maxsplit=1)[0]
    recognized = set()
    for line in header_block.splitlines():
        match = re.match(r'^([A-Za-z0-9-]+):', line)
        if match and match.group(1).lower() in STANDARD_SOURCE_HEADERS:
            recognized.add(match.group(1).lower())
    if len(recognized) < 2:
        raise ValueError(RAW_SOURCE_ERROR)
    validate_email_input(raw_email)


def parse_email_address(address_str: str | None) -> EmailAddress | None:
    """Parse an email address string into EmailAddress object.
    
    Handles formats like:
    - user@example.com
    - John Doe <user@example.com>
    - "John Doe" <user@example.com>
    
    Args:
        address_str: Email address string
        
    Returns:
        EmailAddress or None if parsing fails
    """
    if not address_str or not address_str.strip():
        return None

    address_str = address_str.strip()

    name = None
    address = address_str

    if '<' in address_str and '>' in address_str:
        parts = address_str.rsplit('<', 1)
        if len(parts) == 2:
            name = parts[0].strip().strip('"\'')
            address = parts[1].strip('>')

    name = name if name else None
    address = address.lower().strip()

    try:
        return EmailAddress(name=name, address=address)
    except Exception as e:
        log_event(logger, logging.DEBUG, 'parser.component_failed', component='email_address')
        return None


def parse_email_addresses(address_list: str | None) -> list[EmailAddress]:
    """Parse comma-separated email addresses.
    
    Args:
        address_list: Comma-separated email addresses
        
    Returns:
        List of parsed EmailAddress objects
    """
    if not address_list or not address_list.strip():
        return []

    addresses = []
    for addr_str in address_list.split(','):
        parsed = parse_email_address(addr_str)
        if parsed:
            addresses.append(parsed)

    return addresses


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from text.
    
    Args:
        text: Text to search for URLs
        
    Returns:
        List of unique URLs found
    """
    if not text:
        return []

    urls = [url[:MAX_URL_LENGTH] for url in URL_PATTERN.findall(text) if len(url) <= MAX_URL_LENGTH]
    return list(dict.fromkeys(urls))[:MAX_EXTRACTED_URLS]


def classify_url_extraction(
    *,
    subject: str | None,
    body_text: str,
    body_html: str | None,
    urls: list[str],
    html_links: list[EmailHtmlLink],
    actionable_url_count: int | None = None,
) -> tuple[bool, int, int, str, str]:
    """Describe local URL evidence without guessing hidden destinations."""
    visible_text = ' '.join(filter(None, (subject or '', body_text)))
    link_language_present = bool(LINK_LANGUAGE_PATTERN.search(visible_text))
    html_anchor_count = len(html_links)
    actual_url_count = len(urls)
    actionable_count = actual_url_count if actionable_url_count is None else actionable_url_count
    if actual_url_count and actionable_count:
        return link_language_present, actual_url_count, html_anchor_count, 'extracted', 'url_evidence_extracted'
    if actual_url_count and not actionable_count:
        return link_language_present, actual_url_count, html_anchor_count, 'tracking_only', 'tracking_pixel_only_no_actionable_destination'
    if body_html and re.search(r'<\s*a\b', body_html, re.IGNORECASE):
        return link_language_present, 0, max(1, html_anchor_count), 'partial', 'html_anchor_destination_unavailable'
    if link_language_present:
        return True, 0, html_anchor_count, 'partial', 'link_language_without_url'
    return False, 0, html_anchor_count, 'not_present', 'no_link_evidence'


def get_header_value(message: Any, header_name: str) -> str | None:
    """Safely extract and decode a header value.
    
    Args:
        message: email.message.Message object
        header_name: Name of the header
        
    Returns:
        Decoded header value or None
    """
    value = message.get(header_name)
    if not value:
        return None

    if isinstance(value, str):
        try:
            decoded_parts = decode_header(value)
            result = ''
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    result += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    result += str(part)
            return result.strip() if result else None
        except Exception as e:
            log_event(logger, logging.DEBUG, 'parser.component_failed', component='header_decode')
            return value.strip() if value.strip() else None

    return str(value).strip() if value else None


def extract_body_and_urls(message: Any) -> tuple[str, str | None, list[str]]:
    """Extract plain text and HTML bodies, and all URLs.
    
    Args:
        message: email.message.Message object
        
    Returns:
        Tuple of (plain_text_body, html_body, urls)
    """
    body_text = ''
    body_html = None
    all_urls = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            filename = part.get_filename()

            if content_disposition == 'attachment' or filename:
                continue

            if content_type == 'text/plain':
                try:
                    text = part.get_payload(decode=True)
                    if isinstance(text, bytes):
                        body_text = text.decode('utf-8', errors='ignore')
                    else:
                        body_text = str(text)
                except Exception as e:
                    log_event(logger, logging.DEBUG, 'parser.component_failed', component='plain_text_body')
            elif content_type == 'text/html':
                try:
                    html = part.get_payload(decode=True)
                    if isinstance(html, bytes):
                        body_html = html.decode('utf-8', errors='ignore')
                    else:
                        body_html = str(html)
                except Exception as e:
                    log_event(logger, logging.DEBUG, 'parser.component_failed', component='html_body')
    else:
        try:
            payload = message.get_payload(decode=True)
            if isinstance(payload, bytes):
                decoded = payload.decode('utf-8', errors='ignore')
            else:
                decoded = str(payload)
            if message.get_content_type() == 'text/html':
                body_html = decoded
            else:
                body_text = decoded
        except Exception as e:
            log_event(logger, logging.DEBUG, 'parser.component_failed', component='body')

    all_urls.extend(extract_urls(body_text))
    if body_html:
        _, html_evidence, _, _ = extract_html_semantics(body_html)
        all_urls.extend(evidence.url for evidence in html_evidence)

    return body_text, body_html, list(dict.fromkeys(all_urls))


def extract_attachment_metadata(message: Any) -> list[EmailAttachmentMetadata]:
    """Extract metadata about attachments without saving files.
    
    Args:
        message: email.message.Message object
        
    Returns:
        List of attachment metadata
    """
    attachments = []

    if not message.is_multipart():
        return attachments

    for part in message.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        content_disposition = part.get_content_disposition()
        filename = part.get_filename()
        if content_disposition != 'attachment' and not filename:
            continue

        try:
            if filename:
                decoded_parts = decode_header(filename)
                filename = ''.join(
                    value.decode(encoding or 'utf-8', errors='replace') if isinstance(value, bytes) else value
                    for value, encoding in decoded_parts
                )
            content_type = part.get_content_type()
            decoded_payload = part.get_payload(decode=True)
            size_bytes = len(decoded_payload) if isinstance(decoded_payload, bytes) else 0

            metadata = EmailAttachmentMetadata(
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                disposition=content_disposition,
            )
            attachments.append(metadata)
            if len(attachments) > MAX_ATTACHMENTS:
                raise ValueError('Email contains too many attachments')
        except Exception as e:
            log_event(logger, logging.DEBUG, 'parser.component_failed', component='attachment_metadata')

    return attachments


def parse_email(raw_email: str) -> ParsedEmail:
    """Parse raw email content into a normalized ParsedEmail structure.
    
    Args:
        raw_email: Raw email text or .eml content
        
    Returns:
        ParsedEmail object
        
    Raises:
        ValueError: If input is invalid
    """
    validate_email_input(raw_email)

    try:
        message = message_from_string(raw_email)
    except Exception as e:
        log_event(logger, logging.ERROR, 'parser.failed',
                  reason_code='message_parse_error', exception_class=type(e).__name__)
        raise ValueError('Failed to parse email') from None

    try:
        if sum(1 for _ in message.walk()) > MAX_MIME_PARTS:
            raise ValueError('Email contains too many MIME parts')
    except ValueError:
        raise
    except Exception:
        raise ValueError('Failed to inspect email structure') from None

    subject = get_header_value(message, 'Subject')
    sender = parse_email_address(get_header_value(message, 'From'))
    reply_to = parse_email_address(get_header_value(message, 'Reply-To'))
    recipients = parse_email_addresses(get_header_value(message, 'To'))
    cc = parse_email_addresses(get_header_value(message, 'Cc'))
    date = get_header_value(message, 'Date')
    message_id = get_header_value(message, 'Message-ID')

    body_text, body_html, urls = extract_body_and_urls(message)
    html_links, html_url_evidence, body_visible_text, mailto_evidence = extract_html_semantics(body_html)
    plain_url_evidence = [
        EmailUrlEvidence(url=url, source_type=UrlSourceType.plain_text, user_actionable=True)
        for url in extract_urls(body_text)
    ]
    sender_domain = str(sender.address).rsplit('@', 1)[-1] if sender else None
    url_evidence = []
    for item in list(dict.fromkeys(
        (item.url, item.source_type, item.user_actionable) for item in plain_url_evidence + html_url_evidence
    )):
        evidence = EmailUrlEvidence(url=item[0], source_type=item[1], user_actionable=item[2])
        hostname = _domain_from_indicator(evidence.url)
        evidence = evidence.model_copy(update={
            'external_domain': bool(hostname and sender_domain and not domains_align(sender_domain, hostname)),
            'security_relevance': 'supporting' if evidence.source_type == UrlSourceType.tracking_pixel else 'primary',
        })
        url_evidence.append(evidence)
    actionable_url_count = sum(1 for item in url_evidence if item.user_actionable and item.source_type != UrlSourceType.tracking_pixel)
    tracking_pixel_count = sum(1 for item in url_evidence if item.source_type == UrlSourceType.tracking_pixel)
    external_tracking_pixel_count = sum(1 for item in url_evidence if item.source_type == UrlSourceType.tracking_pixel and item.external_domain is True)
    attachments = extract_attachment_metadata(message)
    link_language_present, actual_url_count, html_anchor_count, url_status, url_reason = classify_url_extraction(
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        html_links=html_links,
        actionable_url_count=actionable_url_count,
    )
    mailto_domains = sorted({domain for item in mailto_evidence for domain in item.destination_domains})
    mailto_action_types = list(dict.fromkeys(item.action_type for item in mailto_evidence))

    headers = {
        key: str(value)
        for key, value in message.items()
        if isinstance(value, str)
    }

    return ParsedEmail(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        recipients=recipients,
        cc=cc,
        date=date,
        message_id=message_id,
        body_text=body_text,
        body_html=body_html,
        body_visible_text=body_visible_text,
        headers=headers,
        extracted_urls=urls,
        url_evidence=url_evidence,
        html_links=html_links,
        link_language_present=link_language_present,
        actual_url_count=actual_url_count,
        html_anchor_count=html_anchor_count,
        url_extraction_status=url_status,
        url_extraction_reason=url_reason,
        actionable_url_count=actionable_url_count,
        tracking_pixel_count=tracking_pixel_count,
        external_tracking_pixel_count=external_tracking_pixel_count,
        mailto_evidence=mailto_evidence,
        mailto_count=len(mailto_evidence),
        actionable_mailto_count=sum(1 for item in mailto_evidence if item.user_actionable),
        mailto_destinations_redacted_or_normalized=mailto_domains,
        mailto_domain_count=len(mailto_domains),
        mailto_personal_provider=any(domain in PERSONAL_MAILBOX_DOMAINS for domain in mailto_domains),
        mailto_action_types=mailto_action_types,
        mailto_action_type=mailto_action_types[0] if mailto_action_types else 'unknown',
        attachments=attachments,
    )
