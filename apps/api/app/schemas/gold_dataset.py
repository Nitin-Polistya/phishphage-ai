"""Contracts for Phase III gold-dataset curation.

These contracts contain metadata and reviewer decisions only. Raw email is not
accepted by this boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.schemas.gemini_review import ReviewLabel, StrictModel


class GoldReviewState(str, Enum):
    pending = 'pending'
    reviewed = 'reviewed'
    needs_second_review = 'needs_second_review'
    approved = 'approved'
    rejected = 'rejected'
    archived = 'archived'

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            normalized = value.strip().lower().replace(' ', '_')
            return next((member for member in cls if member.value == normalized), None)
        return None


class BatchImportFormat(str, Enum):
    csv = 'csv'
    jsonl = 'jsonl'


class SourceClaimedLabel(str, Enum):
    safe = 'safe'
    phishing = 'phishing'
    suspicious = 'suspicious'
    unknown = 'unknown'


class LabelQuality(str, Enum):
    high = 'high'
    medium = 'medium'
    low = 'low'
    unresolved = 'unresolved'


class GoldDatasetReviewInput(StrictModel):
    review_id: UUID | None = None
    sample_hash: str = Field(min_length=1, max_length=128)
    normalized_content_hash: str = Field(min_length=1, max_length=128)
    source_dataset: str = Field(min_length=1, max_length=160)
    source_sample_id: str = Field(min_length=1, max_length=160)
    source_identifier: str = Field(min_length=1, max_length=160)
    campaign_identifier: str = Field(min_length=1, max_length=160)
    reviewer_name: str = Field(min_length=1, max_length=120)
    language: str = Field(min_length=1, max_length=32)
    phishing_label: ReviewLabel = ReviewLabel.unable_to_determine
    label_quality: LabelQuality = LabelQuality.unresolved
    reviewer_confidence: float = Field(ge=0.0, le=1.0)
    review_notes: str = Field(min_length=1, max_length=4000)
    gemini_recommendation: ReviewLabel | None = None
    gemini_reasoning_summary: str | None = Field(default=None, max_length=2000)
    accepted_gemini_recommendation: bool | None = None
    requires_second_review: bool = False
    review_version: str = Field(default='gold-dataset-v1', min_length=1, max_length=80)
    review_timestamp: datetime | None = None
    state: GoldReviewState = GoldReviewState.pending

    @field_validator('review_timestamp')
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('review_timestamp must include a timezone.')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def validate_human_authority(self) -> 'GoldDatasetReviewInput':
        if not self.reviewer_name.strip():
            raise ValueError('A human reviewer name is required.')
        if self.accepted_gemini_recommendation and self.gemini_recommendation is None:
            raise ValueError('Gemini acceptance requires an advisory recommendation.')
        if self.state == GoldReviewState.approved and self.phishing_label == ReviewLabel.unable_to_determine:
            raise ValueError('An indeterminate label cannot be approved.')
        return self


class GoldDatasetReview(StrictModel):
    review_id: UUID
    sample_hash: str
    normalized_content_hash: str
    source_dataset: str
    source_sample_id: str
    source_identifier: str
    campaign_identifier: str
    review_timestamp: datetime
    reviewer_name: str
    language: str
    phishing_label: ReviewLabel
    label_quality: LabelQuality
    reviewer_confidence: float
    review_notes: str
    gemini_recommendation: ReviewLabel | None
    gemini_reasoning_summary: str | None
    accepted_gemini_recommendation: bool | None
    requires_second_review: bool
    review_version: str
    created_at: datetime
    updated_at: datetime
    state: GoldReviewState


class ReviewerDecisionInput(StrictModel):
    reviewer_name: str = Field(min_length=1, max_length=120)
    phishing_label: ReviewLabel
    label_quality: LabelQuality = LabelQuality.unresolved
    reviewer_confidence: float = Field(ge=0.0, le=1.0)
    review_notes: str = Field(min_length=1, max_length=4000)
    requires_second_review: bool = False
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode='after')
    def require_name(self) -> 'ReviewerDecisionInput':
        if not self.reviewer_name.strip():
            raise ValueError('A human reviewer name is required.')
        return self


class ReviewTransitionRequest(StrictModel):
    reviewer_name: str = Field(min_length=1, max_length=120)
    new_state: GoldReviewState
    reason: str = Field(min_length=1, max_length=1000)


class GoldReviewRevisionRequest(StrictModel):
    reviewer_name: str = Field(min_length=1, max_length=120)
    phishing_label: ReviewLabel | None = None
    reviewer_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    review_notes: str | None = Field(default=None, min_length=1, max_length=4000)
    reason: str = Field(min_length=1, max_length=1000)


class AgreementStatistics(StrictModel):
    agreement_id: UUID
    reviewer_a: str
    reviewer_b: str
    sample_count: int = Field(ge=0)
    agreement_count: int = Field(ge=0)
    disagreement_count: int = Field(ge=0)
    agreement_rate: float = Field(ge=0.0, le=1.0)
    cohen_kappa: float = Field(ge=-1.0, le=1.0)
    reviewer_consistency: dict[str, float]
    conflict_statistics: dict[str, int]
    computed_at: datetime
    statistics_version: str


class GoldDatasetDashboard(StrictModel):
    total_samples: int = Field(ge=0)
    review_completion: float = Field(ge=0.0, le=1.0)
    approved_samples: int = Field(ge=0)
    review_queue: dict[str, int]
    reviewer_agreement: AgreementStatistics | None
    label_distribution: dict[str, int]
    language_distribution: dict[str, int]
    confidence_distribution: dict[str, int]
    source_distribution: dict[str, int]
    second_review_count: int = Field(ge=0)


class GoldDatasetExportFile(StrictModel):
    filename: str = Field(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
    status: str = Field(pattern=r'^written$')
    size_bytes: int = Field(ge=0)


class GoldDatasetExportResponse(StrictModel):
    exported_count: int = Field(ge=1)
    exported_at: datetime
    output_location: str = Field(pattern=r'^services/ml/evaluation/private/[A-Za-z0-9._/-]+/$')
    files: list[GoldDatasetExportFile] = Field(min_length=1, max_length=20)
    all_files_written: bool
    privacy_contract: str

    @field_validator('output_location')
    @classmethod
    def reject_output_traversal(cls, value: str) -> str:
        if any(part in {'.', '..'} for part in value.rstrip('/').split('/')):
            raise ValueError('output_location must not contain traversal segments.')
        return value


class AuditTrailEntry(StrictModel):
    audit_id: int = Field(ge=1)
    review_id: UUID
    timestamp: datetime
    reviewer: str
    old_label: ReviewLabel | None
    new_label: ReviewLabel | None
    old_confidence: float | None
    new_confidence: float | None
    reason: str
    old_state: GoldReviewState | None
    new_state: GoldReviewState | None
    bulk_operation_id: UUID | None = None
    batch_id: str | None = None
    operation: str | None = None


class BatchImportRequest(StrictModel):
    format: BatchImportFormat
    content: str = Field(min_length=1, max_length=2_000_000)
    imported_by: str = Field(min_length=1, max_length=120)
    batch_id: str | None = Field(default=None, max_length=80, pattern=r'^[A-Za-z0-9._:-]+$')
    idempotency_key: str | None = Field(default=None, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')


class BatchRowError(StrictModel):
    row_number: int = Field(ge=1)
    code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=240)
    field: str | None = Field(default=None, max_length=80)


class DatasetReviewQueueItem(StrictModel):
    item_id: UUID
    batch_id: str
    row_number: int = Field(ge=1)
    source_sample_id: str
    source_dataset: str
    campaign_id: str
    language: str
    source_claimed_label: SourceClaimedLabel
    current_human_label: ReviewLabel | None
    state: GoldReviewState
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    duplicate_status: str
    duplicate_reasons: list[str] = Field(default_factory=list)
    second_review_required: bool
    second_review_complete: bool
    review_id: UUID | None = None
    subject_preview: str = Field(default='', max_length=300)
    body_excerpt: str = Field(default='', max_length=800)
    sender_domain: str = Field(default='', max_length=253)
    reply_to_domain: str = Field(default='', max_length=253)
    authentication_summary: list[str] = Field(default_factory=list, max_length=10)
    url_domains: list[str] = Field(default_factory=list, max_length=30)
    url_structural_flags: list[str] = Field(default_factory=list, max_length=30)
    attachment_metadata: str = Field(default='', max_length=300)


class BatchReviewResponse(StrictModel):
    batch_id: str
    source_format: BatchImportFormat
    imported_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    imported_at: datetime
    items: list[DatasetReviewQueueItem] = Field(max_length=1000)
    warnings: list[str] = Field(default_factory=list, max_length=100)


class DatasetReviewQueueResponse(StrictModel):
    items: list[DatasetReviewQueueItem] = Field(max_length=100)
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)


class BulkLabelRequest(StrictModel):
    item_ids: list[UUID] = Field(min_length=1, max_length=1000)
    label: ReviewLabel
    reviewer_name: str = Field(min_length=1, max_length=120)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    label_quality: LabelQuality = LabelQuality.high
    requires_second_review: bool = False
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str | None = Field(default=None, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')


class BulkTransitionRequest(StrictModel):
    item_ids: list[UUID] = Field(min_length=1, max_length=1000)
    new_state: GoldReviewState
    reviewer_name: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=1000)
    allow_partial: bool = False
    idempotency_key: str | None = Field(default=None, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')


class BulkReviewSettingsRequest(StrictModel):
    item_ids: list[UUID] = Field(min_length=1, max_length=1000)
    reviewer_name: str = Field(min_length=1, max_length=120)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    requires_second_review: bool | None = None
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str | None = Field(default=None, max_length=160, pattern=r'^[A-Za-z0-9._:-]+$')


class BulkFailure(StrictModel):
    item_id: UUID
    reason: str = Field(min_length=1, max_length=240)


class BulkOperationResponse(StrictModel):
    bulk_operation_id: UUID
    operation: str
    requested_count: int = Field(ge=0)
    affected_count: int = Field(ge=0)
    approved_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    atomic: bool
    failures: list[BulkFailure] = Field(default_factory=list, max_length=100)
    items: list[DatasetReviewQueueItem] = Field(default_factory=list, max_length=100)
