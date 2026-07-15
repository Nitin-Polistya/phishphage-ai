"""Email parsing service."""

from __future__ import annotations

import logging
import re
from email import message_from_string
from email.header import decode_header
from typing import Any

from app.schemas.email import (
    EmailAddress,
    EmailAttachmentMetadata,
    ParsedEmail,
)

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 2 * 1024 * 1024
RAW_SOURCE_ERROR = "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from 'Show original' / 'View source'."
STANDARD_SOURCE_HEADERS = {'from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'}
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\)]+',
    re.IGNORECASE,
)


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
    return list(set(urls))


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
                body_text = payload.decode('utf-8', errors='ignore')
            else:
                body_text = str(payload)
        except Exception as e:
            logger.debug(f'Failed to extract body: {e}')

    all_urls.extend(extract_urls(body_text))
    if body_html:
        all_urls.extend(extract_urls(body_html))

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
        headers=headers,
        extracted_urls=urls,
        attachments=attachments,
    )
