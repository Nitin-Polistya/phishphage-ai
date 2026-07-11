"""Email-related Pydantic schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class EmailAddress(BaseModel):
    """Email address with optional display name."""

    name: str | None = Field(default=None, description='Display name')
    address: EmailStr = Field(..., description='Email address')


class EmailAttachmentMetadata(BaseModel):
    """Metadata about an email attachment without storing the file."""

    filename: str | None = Field(default=None, description='Original filename')
    content_type: str | None = Field(default=None, description='MIME content type')
    size_bytes: int = Field(..., description='Size in bytes')
    disposition: str | None = Field(default=None, description='Content disposition')


class ParsedEmail(BaseModel):
    """Normalized parsed email structure."""

    subject: str | None = Field(default=None, description='Email subject line')
    sender: EmailAddress | None = Field(default=None, description='From address')
    reply_to: EmailAddress | None = Field(default=None, description='Reply-To address')
    recipients: list[EmailAddress] = Field(default_factory=list, description='To addresses')
    cc: list[EmailAddress] = Field(default_factory=list, description='CC addresses')
    date: str | None = Field(default=None, description='Date header value')
    message_id: str | None = Field(default=None, description='Message-ID header value')
    body_text: str = Field(default='', description='Plain text body')
    body_html: str | None = Field(default=None, description='HTML body content')
    headers: dict[str, str] = Field(default_factory=dict, description='All email headers')
    extracted_urls: list[str] = Field(default_factory=list, description='URLs found in email')
    attachments: list[EmailAttachmentMetadata] = Field(
        default_factory=list, description='Attachment metadata'
    )


class EmailParserRequest(BaseModel):
    """Request to parse raw email content."""

    raw_email: str = Field(..., description='Full raw email content or .eml text')
