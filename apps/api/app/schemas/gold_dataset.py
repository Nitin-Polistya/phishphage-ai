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


class GoldDatasetExportResponse(StrictModel):
    export_directory: str
    exported_samples: int = Field(ge=0)
    files: list[str]
    privacy_contract: str


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
