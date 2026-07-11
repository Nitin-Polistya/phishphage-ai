"""Integration tests for email parser API endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestEmailParserEndpoint:
    """Test the POST /api/v1/parser/preview endpoint."""

    def test_valid_email_parsing(self):
        """Test successful email parsing through endpoint."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is a test email body."""
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': email_content}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data['subject'] == 'Test Email'
        assert data['sender']['address'] == 'sender@example.com'
        assert len(data['recipients']) > 0

    def test_empty_email_input(self):
        """Test endpoint rejects empty email input."""
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': ''}
        )
        
        assert response.status_code == 400
        assert 'cannot be empty' in response.json()['detail']

    def test_oversized_email_input(self):
        """Test endpoint rejects oversized email input."""
        huge_email = 'From: test@test.com\nBody: ' + ('x' * (3 * 1024 * 1024))
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': huge_email}
        )
        
        assert response.status_code == 400
        assert 'exceeds maximum size' in response.json()['detail']

    def test_missing_raw_email_field(self):
        """Test endpoint returns 422 for missing raw_email field."""
        response = client.post(
            '/api/v1/parser/preview',
            json={}
        )
        
        assert response.status_code == 422

    def test_invalid_json(self):
        """Test endpoint returns 422 for invalid JSON."""
        response = client.post(
            '/api/v1/parser/preview',
            data='invalid json',
            headers={'Content-Type': 'application/json'}
        )
        
        assert response.status_code == 422

    def test_email_with_urls(self):
        """Test endpoint extracts URLs correctly."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Link Email

Click here: https://example.com/verify?token=abc123"""
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': email_content}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data['extracted_urls']) > 0
        assert any('example.com' in url for url in data['extracted_urls'])

    def test_email_with_attachments(self):
        """Test endpoint extracts attachment metadata."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Email with Attachment
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

See attached
--boundary123
Content-Type: application/pdf; name="document.pdf"
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJeLj
--boundary123--"""
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': email_content}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data['attachments']) > 0
        assert data['attachments'][0]['filename'] == 'document.pdf'

    def test_response_schema_validation(self):
        """Test endpoint response conforms to ParsedEmail schema."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test

Body"""
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': email_content}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify all required fields are present
        required_fields = [
            'subject', 'sender', 'recipients', 'cc',
            'body_text', 'headers', 'extracted_urls', 'attachments'
        ]
        for field in required_fields:
            assert field in data, f'Missing required field: {field}'

    def test_endpoint_route_exists(self):
        """Test endpoint is registered at correct route."""
        response = client.options('/api/v1/parser/preview')
        assert response.status_code == 405  # Method Not Allowed (GET not allowed)

    def test_multipart_email_response(self):
        """Test multipart email is parsed and returned correctly."""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Multipart Email
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text version
--boundary123
Content-Type: text/html

<html><body>HTML version</body></html>
--boundary123--"""
        
        response = client.post(
            '/api/v1/parser/preview',
            json={'raw_email': email_content}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert 'Plain text version' in data['body_text']
        assert data['body_html'] is not None
        assert '<html>' in data['body_html'].lower()
