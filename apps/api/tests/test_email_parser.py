"""Tests for email parser service and endpoint."""

from __future__ import annotations

import pytest

from app.schemas.email import EmailAddress, EmailAttachmentMetadata, ParsedEmail
from app.services.email_parser import (
    extract_urls,
    parse_email,
    parse_email_address,
    parse_email_addresses,
)


class TestParseEmailAddress:
    """Test email address parsing."""

    def test_simple_email(self):
        """Test parsing a simple email address."""
        result = parse_email_address('user@example.com')
        assert result is not None
        assert result.address == 'user@example.com'
        assert result.name is None

    def test_email_with_display_name(self):
        """Test parsing email with display name."""
        result = parse_email_address('John Doe <john@example.com>')
        assert result is not None
        assert result.address == 'john@example.com'
        assert result.name == 'John Doe'

    def test_email_with_quoted_name(self):
        """Test parsing email with quoted display name."""
        result = parse_email_address('"Jane Smith" <jane@example.com>')
        assert result is not None
        assert result.address == 'jane@example.com'
        assert result.name == 'Jane Smith'

    def test_empty_input(self):
        """Test parsing empty input."""
        result = parse_email_address(None)
        assert result is None

    def test_whitespace_only(self):
        """Test parsing whitespace-only input."""
        result = parse_email_address('   ')
        assert result is None


class TestParseEmailAddresses:
    """Test comma-separated email address parsing."""

    def test_single_address(self):
        """Test parsing single address."""
        result = parse_email_addresses('user@example.com')
        assert len(result) == 1
        assert result[0].address == 'user@example.com'

    def test_multiple_addresses(self):
        """Test parsing multiple addresses."""
        result = parse_email_addresses('alice@example.com, bob@example.com, charlie@example.com')
        assert len(result) == 3
        assert result[0].address == 'alice@example.com'
        assert result[1].address == 'bob@example.com'
        assert result[2].address == 'charlie@example.com'

    def test_empty_input(self):
        """Test parsing empty input."""
        result = parse_email_addresses(None)
        assert result == []


class TestExtractUrls:
    """Test URL extraction."""

    def test_single_http_url(self):
        """Test extracting single HTTP URL."""
        text = 'Visit http://example.com for more info'
        result = extract_urls(text)
        assert 'http://example.com' in result

    def test_single_https_url(self):
        """Test extracting single HTTPS URL."""
        text = 'Go to https://secure.example.com now'
        result = extract_urls(text)
        assert 'https://secure.example.com' in result

    def test_multiple_urls(self):
        """Test extracting multiple URLs."""
        text = 'Check https://example.com and http://another.com'
        result = extract_urls(text)
        assert len(result) >= 2
        assert any('example.com' in url for url in result)
        assert any('another.com' in url for url in result)

    def test_url_with_path_and_query(self):
        """Test URL with path and query string."""
        text = 'Visit https://example.com/path?id=123&token=abc'
        result = extract_urls(text)
        assert any('example.com/path' in url for url in result)

    def test_no_urls(self):
        """Test text with no URLs."""
        text = 'This is plain text with no links'
        result = extract_urls(text)
        assert result == []

    def test_empty_input(self):
        """Test empty input."""
        result = extract_urls('')
        assert result == []


class TestParseEmail:
    """Test complete email parsing."""

    def test_plain_text_email(self):
        """Test parsing simple plain text email."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a test email body."""
        result = parse_email(email_content)

        assert result.subject == 'Test Email'
        assert result.sender is not None
        assert result.sender.address == 'sender@example.com'
        assert len(result.recipients) > 0
        assert result.recipients[0].address == 'recipient@example.com'
        assert 'test email' in result.body_text.lower()

    def test_email_with_multiple_recipients(self):
        """Test parsing email with multiple recipients."""
        email_content = """From: sender@example.com
To: alice@example.com, bob@example.com
Cc: charlie@example.com
Subject: Team Update

Team meeting at 3pm."""
        result = parse_email(email_content)

        assert len(result.recipients) >= 2
        assert len(result.cc) >= 1

    def test_email_with_urls(self):
        """Test extracting URLs from email body."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Important Link

Click here: https://example.com/verify?token=abc123
Also check http://another-site.com"""
        result = parse_email(email_content)

        assert len(result.extracted_urls) >= 2
        assert any('example.com' in url for url in result.extracted_urls)

    def test_email_with_reply_to(self):
        """Test parsing Reply-To header."""
        email_content = """From: sender@example.com
Reply-To: support@example.com
To: recipient@example.com
Subject: Support Request

Please help."""
        result = parse_email(email_content)

        assert result.reply_to is not None
        assert result.reply_to.address == 'support@example.com'

    def test_email_with_display_names(self):
        """Test parsing email with display names in headers."""
        email_content = """From: "John Doe" <john@example.com>
To: "Jane Smith" <jane@example.com>
Subject: Hello

Hi Jane!"""
        result = parse_email(email_content)

        assert result.sender is not None
        assert result.sender.name == 'John Doe'
        if result.recipients:
            assert result.recipients[0].name == 'Jane Smith'

    def test_empty_email_input(self):
        """Test parsing empty email raises ValueError."""
        with pytest.raises(ValueError, match='cannot be empty'):
            parse_email('')

    def test_whitespace_only_email(self):
        """Test parsing whitespace-only email raises ValueError."""
        with pytest.raises(ValueError, match='cannot be empty'):
            parse_email('   \n\n  ')

    def test_oversized_email(self):
        """Test parsing oversized email raises ValueError."""
        huge_email = 'From: test@test.com\nBody: ' + ('x' * (3 * 1024 * 1024))
        with pytest.raises(ValueError, match='exceeds maximum size'):
            parse_email(huge_email)

    def test_html_email_body(self):
        """Test parsing email with HTML content."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: HTML Email
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text version
--boundary123
Content-Type: text/html

<html><body><p>HTML version</p></body></html>
--boundary123--"""
        result = parse_email(email_content)

        assert 'Plain text version' in result.body_text
        if result.body_html:
            assert '<html>' in result.body_html.lower()

    def test_email_with_attachment_metadata(self):
        """Test parsing email with attachment metadata."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Email with Attachment
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

See attached document
--boundary123
Content-Type: application/pdf; name="document.pdf"
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJeLj
--boundary123--"""
        result = parse_email(email_content)

        assert len(result.attachments) > 0
        attachment = result.attachments[0]
        assert attachment.filename == 'document.pdf'
        assert 'pdf' in attachment.content_type.lower()

    def test_message_id_and_date_extraction(self):
        """Test extraction of Message-ID and Date headers."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test
Message-ID: <12345@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000

Body text"""
        result = parse_email(email_content)

        assert result.message_id == '<12345@example.com>'
        assert 'Mon' in (result.date or '')


class TestEmailParserValidation:
    """Test input validation."""

    def test_size_limit_validation(self):
        """Test that emails exceeding size limit are rejected."""
        oversized = 'From: test@test.com\n\n' + ('x' * (3 * 1024 * 1024))
        with pytest.raises(ValueError):
            parse_email(oversized)
