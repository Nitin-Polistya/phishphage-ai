"""Strict, advisory-only contracts for the local dataset-review workspace."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ReviewLabel(str, Enum):
    safe = 'safe'
    suspicious = 'suspicious'
    phishing = 'phishing'
    unable_to_determine = 'unable_to_determine'


class GeminiEvidenceCategory(str, Enum):
    identity = 'identity'
    authentication = 'authentication'
    routing = 'routing'
    content = 'content'
    url = 'url'
    attachment = 'attachment'
    context = 'context'
    uncertainty = 'uncertainty'


class EvidenceStrength(str, Enum):
    weak = 'weak'
    moderate = 'moderate'
    strong = 'strong'


class EvidenceSupport(str, Enum):
    safe = 'safe'
    suspicious = 'suspicious'
    phishing = 'phishing'
    neutral = 'neutral'


class ReviewMode(str, Enum):
    independent = 'independent'
    ai_assisted = 'ai_assisted'


class ReviewStatus(str, Enum):
    unreviewed = 'unreviewed'
    preliminary_reviewed = 'preliminary_reviewed'
    gemini_suggested = 'gemini_suggested'
    single_reviewer_adjudicated = 'single_reviewer_adjudicated'
    second_review_pending = 'second_review_pending'
    disagreement = 'disagreement'
    dual_reviewer_adjudicated = 'dual_reviewer_adjudicated'
    excluded = 'excluded'
    insufficient_evidence = 'insufficient_evidence'


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class GeminiEvidenceItem(StrictModel):
    category: GeminiEvidenceCategory
    title: str = Field(min_length=1, max_length=160)
    explanation: str = Field(min_length=1, max_length=800)
    evidence_strength: EvidenceStrength
    supports: EvidenceSupport


class ProviderUsage(StrictModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class SanitizedReviewInput(StrictModel):
    """Only privacy-reduced evidence may cross the dataset-review API."""

    sample_id: str = Field(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')
    subject: str | None = Field(default=None, max_length=300)
    display_name: str | None = Field(default=None, max_length=160)
    sender_domain: str | None = Field(default=None, max_length=253)
    reply_to_domain: str | None = Field(default=None, max_length=253)
    return_path_domain: str | None = Field(default=None, max_length=253)
    authentication_summary: list[str] = Field(default_factory=list, max_length=10)
    body_excerpt: str = Field(default='', max_length=8000)
    visible_html_text: str = Field(default='', max_length=8000)
    url_domains: list[str] = Field(default_factory=list, max_length=30)
    url_structural_flags: list[str] = Field(default_factory=list, max_length=30)
    attachment_extension: str | None = Field(default=None, max_length=32)
    attachment_mime: str | None = Field(default=None, max_length=160)
    parser_evidence: list[str] = Field(default_factory=list, max_length=30)
    candidate_campaign_category: str | None = Field(default=None, max_length=120)

    @field_validator('authentication_summary', 'url_structural_flags', 'parser_evidence', mode='before')
    @classmethod
    def require_string_lists(cls, value: object) -> object:
        if value is None:
            return []
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError('Evidence lists must contain strings.')
        return value


class SanitizedReviewPayload(StrictModel):
    sample_id: str = Field(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')
    subject: str = Field(default='', max_length=300)
    display_name: str = Field(default='', max_length=160)
    sender_domain: str = Field(default='', max_length=253)
    reply_to_domain: str = Field(default='', max_length=253)
    return_path_domain: str = Field(default='', max_length=253)
    authentication_summary: list[str] = Field(default_factory=list, max_length=10)
    body_excerpt: str = Field(default='', max_length=8000)
    visible_html_text: str = Field(default='', max_length=8000)
    url_domains: list[str] = Field(default_factory=list, max_length=30)
    url_structural_flags: list[str] = Field(default_factory=list, max_length=30)
    attachment_extension: str = Field(default='', max_length=32)
    attachment_mime: str = Field(default='', max_length=160)
    parser_evidence: list[str] = Field(default_factory=list, max_length=30)
    candidate_campaign_category: str = Field(default='', max_length=120)
    model_name: str = Field(min_length=1, max_length=160)
    prompt_version: str = Field(min_length=1, max_length=80)
    sanitized_payload_hash: str = Field(pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def check_text_budget(self) -> 'SanitizedReviewPayload':
        if len(self.subject) > 300 or len(self.body_excerpt) > 8000:
            raise ValueError('Sanitized subject or body exceeds the configured limit.')
        return self


class DatasetReviewPreviewResponse(StrictModel):
    enabled: bool
    payload: SanitizedReviewPayload | None = None
    payload_bytes: int = Field(default=0, ge=0)
    payload_hash: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    sent_fields: list[str] = Field(default_factory=list)
    notice: str


class GeminiProviderSuggestion(StrictModel):
    """The provider-owned portion of a Gemini advisory response."""

    suggested_label: ReviewLabel = Field(description='Advisory label for human review.')
    confidence: float = Field(ge=0.0, le=1.0, description='Provider confidence from 0 through 1.')
    summary: str = Field(min_length=1, max_length=1200, description='Concise advisory summary.')
    evidence: list[GeminiEvidenceItem] = Field(default_factory=list, max_length=12)
    contrary_evidence: list[GeminiEvidenceItem] = Field(default_factory=list, max_length=12)
    claimed_organization: str | None = Field(default=None, max_length=160)
    sender_domain_assessment: str = Field(max_length=500)
    authentication_assessment: str = Field(max_length=500)
    action_requested: str | None = Field(default=None, max_length=500)
    likely_campaign: str | None = Field(default=None, max_length=160)
    missing_evidence: list[str] = Field(default_factory=list, max_length=12)
    ambiguity_notes: list[str] = Field(default_factory=list, max_length=12)
    reviewer_questions: list[str] = Field(default_factory=list, max_length=12)
    safety_notes: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode='after')
    def reject_duplicate_evidence(self) -> 'GeminiProviderSuggestion':
        titles = [item.title.casefold() for item in [*self.evidence, *self.contrary_evidence]]
        if len(titles) != len(set(titles)):
            raise ValueError('Evidence items must have unique titles.')
        return self


class GeminiReviewSuggestion(GeminiProviderSuggestion):
    """Validated provider advice plus server-owned provenance metadata."""

    suggestion_id: str = Field(min_length=1, max_length=120)
    sample_id: str = Field(min_length=1, max_length=160)
    model_name: str = Field(min_length=1, max_length=160)
    prompt_version: str = Field(min_length=1, max_length=80)
    sanitized_payload_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    generated_at: datetime
    provider_usage: ProviderUsage = Field(default_factory=ProviderUsage)

    @field_validator('generated_at')
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('generated_at must include a timezone.')
        return value.astimezone(timezone.utc)

class GeminiReviewSuggestRequest(StrictModel):
    payload: SanitizedReviewPayload
    consent: bool = False
    review_mode: ReviewMode = ReviewMode.independent
    reviewer_alias: str = Field(min_length=1, max_length=80)
    preliminary_label: ReviewLabel | None = None
    preliminary_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    preliminary_notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode='after')
    def validate_independent_order(self) -> 'GeminiReviewSuggestRequest':
        if self.review_mode == ReviewMode.independent and self.preliminary_label is None:
            raise ValueError('Independent review requires a preliminary human label before Gemini is shown.')
        if self.preliminary_label is not None and not self.preliminary_notes:
            raise ValueError('A preliminary human note is required with a preliminary label.')
        return self


class HumanReviewRequest(StrictModel):
    sample_id: str = Field(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')
    reviewer_id: str = Field(min_length=1, max_length=80)
    reviewer_role: str = Field(default='reviewer_1', pattern=r'^(reviewer_1|reviewer_2|adjudicator)$')
    review_mode: ReviewMode = ReviewMode.independent
    label: ReviewLabel
    confidence: float = Field(ge=0.0, le=1.0)
    notes: str = Field(min_length=1, max_length=2000)
    change_reason: str | None = Field(default=None, max_length=800)
    content_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    preliminary_label: ReviewLabel | None = None
    preliminary_notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode='after')
    def require_change_reason_if_ai_influenced(self) -> 'HumanReviewRequest':
        if self.label == ReviewLabel.unable_to_determine:
            raise ValueError('Final human labels must be safe, suspicious, or phishing.')
        if self.review_mode == ReviewMode.independent and (self.preliminary_label is None or not self.preliminary_notes):
            raise ValueError('Independent review requires a preliminary human label and note.')
        if self.review_mode == ReviewMode.ai_assisted and self.change_reason is None:
            raise ValueError('AI-assisted reviews require a provenance change reason.')
        return self


class DatasetReviewStatus(StrictModel):
    enabled: bool
    local_only: bool
    gemini_enabled: bool
    configured: bool
    provider_ready: bool
    model_name: str | None
    prompt_version: str
    session_limit: int
    daily_limit: int
    batch_enabled: bool
    storage: str
    notice: str


class DatasetReviewRecord(StrictModel):
    sample_id: str
    content_hash: str
    sanitized_payload_hash: str
    status: ReviewStatus
    review_mode: ReviewMode
    preliminary_human_label: ReviewLabel | None = None
    preliminary_confidence: float | None = None
    preliminary_notes: str | None = None
    gemini_suggestion: GeminiReviewSuggestion | None = None
    final_human_label: ReviewLabel | None = None
    final_confidence: float | None = None
    reviewer_alias: str | None = None
    label_changed_after_ai: bool = False
    change_reason: str | None = None
    updated_at: datetime


class ReviewerQueueItem(StrictModel):
    sample_id: str = Field(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')
    subject_redacted: str = Field(default='', max_length=300)
    sender_domain: str = Field(default='', max_length=253)
    reply_to_domain: str = Field(default='', max_length=253)
    authentication_summary: list[str] = Field(default_factory=list, max_length=10)
    body_excerpt: str = Field(default='', max_length=8000)
    url_domains: list[str] = Field(default_factory=list, max_length=30)
    url_structural_flags: list[str] = Field(default_factory=list, max_length=30)
    attachment_extension: str = Field(default='', max_length=32)
    attachment_mime: str = Field(default='', max_length=160)
    candidate_category: str = Field(default='', max_length=120)


class ReviewerQueueExportRequest(StrictModel):
    reviewer_id: str = Field(min_length=1, max_length=80)
    queue: list[ReviewerQueueItem] = Field(min_length=1, max_length=500)
    package_version: str = Field(default='dataset-review-package-1', pattern=r'^dataset-review-package-1$')


class ReviewerQueueExportResponse(StrictModel):
    reviewer_id: str
    package_version: str
    package_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    csv_text: str = Field(min_length=1, max_length=2_000_000)


class ReviewerDecisionImportRequest(StrictModel):
    reviewer_id: str = Field(min_length=1, max_length=80)
    csv_text: str = Field(min_length=1, max_length=2_000_000)
    package_hash: str = Field(pattern=r'^[a-f0-9]{64}$')


class ReviewerDecisionImportResponse(StrictModel):
    reviewer_id: str
    package_hash: str
    decisions: list[dict[str, str | float]] = Field(max_length=500)
    disagreement_queue: list[str] = Field(default_factory=list, max_length=500)
