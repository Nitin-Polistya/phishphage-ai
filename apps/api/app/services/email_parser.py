"""Email parsing service."""

from __future__ import annotations

import logging
import re
from email import message_from_string
from email.header import decode_header
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from app.schemas.email import (
    EmailAddress,
    EmailAttachmentMetadata,
    EmailHtmlLink,
    EmailUrlEvidence,
    ParsedEmail,
    UrlSourceType,
)
from app.services.domain_utils import domains_align

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 2 * 1024 * 1024
RAW_SOURCE_ERROR = "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from 'Show original' / 'View source'."
STANDARD_SOURCE_HEADERS = {'from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'}
URL_PATTERN = re.compile(
    r'h(?:tt|xx)ps?://[^\s<>"\'\)]+',
    re.IGNORECASE,
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


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[EmailHtmlLink] = []
        self.url_evidence: list[EmailUrlEvidence] = []
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
        logger.debug('Failed to parse HTML anchors', exc_info=True)
    return parser.links


def extract_html_semantics(html: str | None) -> tuple[list[EmailHtmlLink], list[EmailUrlEvidence], str]:
    if not html:
        return [], [], ''
    parser = _AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        logger.debug('Failed to parse HTML semantics', exc_info=True)
    visible_text = re.sub(r'\s+', ' ', ' '.join(parser.visible_text_parts)).strip()
    return parser.links, parser.url_evidence, visible_text


def validate_email_input(raw_email: str) -> None:
    """Validate email input before parsing.
    
    Args:
        raw_email: Raw email content
        
    Raises:
        ValueError: If input is invalid
    """
    if not raw_email or not raw_email.strip():
        raise ValueError('Email content cannot be empty')

    if len(raw_email.encode('utf-8')) > MAX_EMAIL_SIZE_BYTES:
        raise ValueError(f'Email exceeds maximum size of {MAX_EMAIL_SIZE_BYTES} bytes')


def validate_rfc822_source(raw_email: str) -> None:
    """Reject copied display text while accepting a real RFC822 header block."""
    validate_email_input(raw_email)
    header_block = re.split(r'\r?\n\r?\n', raw_email, maxsplit=1)[0]
    recognized = set()
    for line in header_block.splitlines():
        match = re.match(r'^([A-Za-z0-9-]+):', line)
        if match and match.group(1).lower() in STANDARD_SOURCE_HEADERS:
            recognized.add(match.group(1).lower())
    if len(recognized) < 2:
        raise ValueError(RAW_SOURCE_ERROR)


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
        logger.debug(f'Failed to parse email address "{address_str}": {e}')
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

    urls = URL_PATTERN.findall(text)
    return list(dict.fromkeys(urls))


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
            logger.debug(f'Failed to decode header "{header_name}": {e}')
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
                    logger.debug(f'Failed to extract plain text body: {e}')
            elif content_type == 'text/html':
                try:
                    html = part.get_payload(decode=True)
                    if isinstance(html, bytes):
                        body_html = html.decode('utf-8', errors='ignore')
                    else:
                        body_html = str(html)
                except Exception as e:
                    logger.debug(f'Failed to extract HTML body: {e}')
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
            logger.debug(f'Failed to extract body: {e}')

    all_urls.extend(extract_urls(body_text))
    if body_html:
        _, html_evidence, _ = extract_html_semantics(body_html)
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
        except Exception as e:
            logger.debug(f'Failed to extract attachment metadata: {e}')

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
        logger.error(f'Failed to parse email: {e}')
        raise ValueError(f'Failed to parse email: {e}')

    subject = get_header_value(message, 'Subject')
    sender = parse_email_address(get_header_value(message, 'From'))
    reply_to = parse_email_address(get_header_value(message, 'Reply-To'))
    recipients = parse_email_addresses(get_header_value(message, 'To'))
    cc = parse_email_addresses(get_header_value(message, 'Cc'))
    date = get_header_value(message, 'Date')
    message_id = get_header_value(message, 'Message-ID')

    body_text, body_html, urls = extract_body_and_urls(message)
    html_links, html_url_evidence, body_visible_text = extract_html_semantics(body_html)
    plain_url_evidence = [
        EmailUrlEvidence(url=url, source_type=UrlSourceType.plain_text, user_actionable=True)
        for url in extract_urls(body_text)
    ]
    url_evidence = list(dict.fromkeys(
        (item.url, item.source_type, item.user_actionable) for item in plain_url_evidence + html_url_evidence
    ))
    attachments = extract_attachment_metadata(message)

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
        url_evidence=[
            EmailUrlEvidence(url=url, source_type=source_type, user_actionable=user_actionable)
            for url, source_type, user_actionable in url_evidence
        ],
        html_links=html_links,
        attachments=attachments,
    )
