"""Email-related Pydantic schemas."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


RISKY_ATTACHMENT_EXTENSIONS = {
    '.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.iso', '.img', '.zip', '.rar',
    '.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm',
}


class AnalysisInputMode(str, Enum):
    quick_paste = 'quick_paste'
    raw_email = 'raw_email'
    eml_upload = 'eml_upload'


class UrlSourceType(str, Enum):
    anchor_href = 'anchor_href'
    plain_text = 'plain_text'
    form_action = 'form_action'
    image_src = 'image_src'
    css_resource = 'css_resource'
    tracking_pixel = 'tracking_pixel'
    document_metadata = 'document_metadata'
    namespace_or_dtd = 'namespace_or_dtd'


class EmailAddress(BaseModel):
    """Email address with optional display name."""

    name: str | None = Field(default=None, description='Display name')
    address: EmailStr = Field(..., description='Email address')


class EmailAttachmentMetadata(BaseModel):
    """Metadata about an email attachment without storing the file."""

    filename: str | None = Field(default=None, description='Original filename')
    content_type: str | None = Field(default=None, description='MIME content type')
    size_bytes: int = Field(..., ge=0, description='Size in bytes')
    disposition: str | None = Field(default=None, description='Content disposition')
    extension: str | None = Field(default=None, description='Lowercase file extension')
    suspicious_extension: bool = Field(default=False, description='Whether the extension is risky')

    @model_validator(mode='after')
    def derive_extension_status(self) -> 'EmailAttachmentMetadata':
        if self.filename and not self.extension:
            suffix = self.filename.rsplit('.', 1)
            self.extension = f'.{suffix[1].lower()}' if len(suffix) == 2 else None
        if self.extension:
            self.extension = self.extension.lower()
            self.suspicious_extension = self.extension in RISKY_ATTACHMENT_EXTENSIONS
        return self


class EmailHtmlLink(BaseModel):
    """Locally parsed anchor evidence; no destination is fetched."""

    visible_text: str = ''
    href: str
    visible_domain: str | None = None
    href_domain: str | None = None
    domain_mismatch: bool = False


class EmailUrlEvidence(BaseModel):
    """A locally extracted URL with the HTML/text context where it appeared."""

    url: str
    source_type: UrlSourceType
    user_actionable: bool = False


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
    body_visible_text: str = Field(default='', description='Decoded visible text extracted from HTML')
    headers: dict[str, str] = Field(default_factory=dict, description='All email headers')
    extracted_urls: list[str] = Field(default_factory=list, description='URLs found in email')
    url_evidence: list[EmailUrlEvidence] = Field(default_factory=list, description='URLs with source semantics')
    html_links: list[EmailHtmlLink] = Field(default_factory=list, description='Locally parsed HTML anchors')
    attachments: list[EmailAttachmentMetadata] = Field(
        default_factory=list, description='Attachment metadata'
    )


class EmailParserRequest(BaseModel):
    """Request to parse raw email content."""

    raw_email: str = Field(..., description='Full raw email content or .eml text')


class AnalysisPreviewRequest(BaseModel):
    """Mode-aware analysis request; legacy raw_email requests remain valid."""

    input_mode: AnalysisInputMode = AnalysisInputMode.raw_email
    raw_email: str | None = None
    sender_name: str | None = Field(default=None, max_length=200)
    sender_email: EmailStr | None = None
    recipient_name: str | None = Field(default=None, max_length=200)
    recipient_email: EmailStr | None = None
    reply_to: EmailStr | None = None
    subject: str | None = Field(default=None, max_length=998)
    body: str | None = None
    attachments: list[EmailAttachmentMetadata] = Field(default_factory=list, max_length=25)

    @field_validator('sender_email', 'recipient_email', 'reply_to', mode='before')
    @classmethod
    def blank_email_to_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator('sender_name', 'recipient_name', 'subject', mode='before')
    @classmethod
    def blank_optional_text_to_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @model_validator(mode='after')
    def validate_mode_content(self) -> 'AnalysisPreviewRequest':
        if self.input_mode == AnalysisInputMode.quick_paste:
            if not self.body or not self.body.strip():
                raise ValueError('Email body is required for Quick Paste')
        elif self.raw_email is None:
            raise ValueError('Raw email content is required for this input mode')
        return self
