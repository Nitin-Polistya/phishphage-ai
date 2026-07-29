"""Pydantic schemas for rule-based analysis results."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.schemas.email import ParsedEmail


class ThreatSeverity(str, Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'


class ThreatClassification(str, Enum):
    safe = 'safe'
    suspicious = 'suspicious'
    phishing = 'phishing'


class ThreatSignal(BaseModel):
    code: str = Field(..., description='Unique signal code')
    category: str = Field(..., description='Signal category')
    severity: ThreatSeverity = Field(..., description='Signal severity')
    title: str = Field(..., description='Short title')
    description: str = Field(..., description='Concise description')
    score: Annotated[int, Field(ge=0, le=100)] = Field(..., description='Signal score contribution')
    evidence: str | None = Field(default=None, description='Short evidence string')
    recommendation: str = Field(
        default='Verify the message through a trusted channel before taking action.',
        description='Action the recipient should take in response to this finding',
    )
    # Explainability metadata is deliberately separate from score. A finding
    # can be high-concern context without adding arbitrary points to a model or
    # rule score.
    source_engine: str = Field(default='rules', description='Engine that produced the finding')
    evidence_type: str = Field(default='rule_finding', description='Evidence provenance category')
    user_impact: str | None = Field(default=None, description='Why this finding matters to the recipient')
    tone: str = Field(default='informational', description='Semantic concern tone independent of score')
    confidence: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    mapped_title: str | None = None
    mapped_description: str | None = None
    contributes_to_score: bool = True
    provenance: str | None = Field(default=None, description='Safe, local evidence provenance')


class AnalysisResult(BaseModel):
    classification: ThreatClassification = Field(...)
    risk_score: Annotated[int, Field(ge=0, le=100)] = Field(...)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(...)
    signals: list[ThreatSignal] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    engine_version: str = Field(...)
    engineered_features: dict[str, int | float | str] = Field(default_factory=dict)
    feature_explanations: dict[str, str] = Field(default_factory=dict)
    feature_evidence: dict[str, str] = Field(default_factory=dict)


class MLStatus(str, Enum):
    available = 'available'
    unavailable = 'unavailable'


class MLAnalysisResult(BaseModel):
    status: MLStatus
    prediction: str | None = Field(default=None, description="Predicted label when ML is available")
    phishing_probability: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    legitimate_probability: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    model_version: str | None = None
    reason: str | None = None
    decision_threshold: Annotated[float | None, Field(ge=0.0, le=1.0)] = None


class AnalysisCompletenessState(str, Enum):
    body_text_only = 'body_text_only'
    structured_fields = 'structured_fields'
    html_content = 'html_content'
    complete_raw_email = 'complete_raw_email'


class AnalysisCompletenessLevel(str, Enum):
    complete = 'complete'
    partial = 'partial'
    incomplete = 'incomplete'
    stale = 'stale'
    unavailable = 'unavailable'


class AnalysisCompleteness(BaseModel):
    state: AnalysisCompletenessState
    limited_evidence: bool
    warning: str | None = None
    has_from_header: bool = False
    has_reply_to: bool = False
    has_return_path: bool = False
    has_authentication_results: bool = False
    has_spf_result: bool = False
    has_dkim_result: bool = False
    has_dmarc_result: bool = False
    has_html_source: bool = False
    has_real_href_destinations: bool = False
    has_attachment_metadata: bool = False
    has_complete_raw_headers: bool = False
    analysis_state: AnalysisCompletenessLevel = AnalysisCompletenessLevel.partial
    missing_evidence: list[str] = Field(default_factory=list)
    incomplete_reason_codes: list[str] = Field(default_factory=list)
    parser_success: bool = True
    rules_available: bool = False
    ml_available: bool = False
    fusion_available: bool = False


class EngineAgreement(str, Enum):
    agreement = 'agreement'
    disagreement = 'disagreement'
    ml_unavailable = 'ml_unavailable'


class AnalysisFreshness(str, Enum):
    current = 'current'
    stale = 'stale'


class DecisionSafetyStatus(str, Enum):
    eligible = 'eligible'
    needs_review = 'needs_review'
    unable_to_verify = 'unable_to_verify'
    rescan_required = 'rescan_required'


class PresentationState(str, Enum):
    safe = 'safe'
    suspicious = 'suspicious'
    phishing = 'phishing'
    needs_review = 'needs_review'
    unable_to_verify = 'unable_to_verify'
    rescan_required = 'rescan_required'


class AuthenticationState(str, Enum):
    passed = 'pass'
    failed = 'fail'
    inconclusive = 'inconclusive'
    missing = 'missing'
    unavailable = 'unavailable'
    malformed = 'malformed'
    conflicting = 'conflicting'


class AuthenticationEvidence(BaseModel):
    mechanism: str
    state: AuthenticationState
    domain: str | None = None
    aligned_with_from: bool | None = None
    result: str | None = None
    display_label: str = 'Status unavailable'
    detail: str | None = None


class DecisionResult(BaseModel):
    classification: ThreatClassification = Field(...)
    risk_score: Annotated[int, Field(ge=0, le=100)] = Field(...)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(...)
    fusion_reason: str | None = None
    limited_authentication_evidence: bool = False
    decision_source: str = 'fusion'
    fusion_performed: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    fusion_policy_version: str = 'asymmetric-safety-v1'
    fusion_inputs: dict[str, Any] = Field(default_factory=dict)
    fusion_components: list[str] = Field(default_factory=list)
    rule_weight: float = 0.5
    ml_weight: float = 0.5
    applied_floor: bool = False
    applied_floor_reason: str | None = None
    dominant_evidence_source: str = 'balanced'
    disagreement_resolution: str | None = None
    safety_floor_applied: bool = False
    safety_floor_rule_id: str | None = None
    pre_floor_score: int | None = Field(default=None, ge=0, le=100)
    post_floor_score: int | None = Field(default=None, ge=0, le=100)
    evidence_families: list[str] = Field(default_factory=list)
    high_confidence_rule_evidence: bool = False
    protective_evidence: list[str] = Field(default_factory=list)


class UnifiedAnalysisResponse(BaseModel):
    parser: ParsedEmail = Field(...)
    rule_analysis: AnalysisResult = Field(...)
    ml_analysis: MLAnalysisResult = Field(...)
    decision: DecisionResult = Field(...)
    recommendations: list[str] = Field(default_factory=list)
    analysis_completeness: AnalysisCompleteness
    engine_agreement: EngineAgreement
    rule_raw_score: Annotated[int | None, Field(ge=0, le=100)] = None
    rule_adjusted_score: Annotated[int | None, Field(ge=0, le=100)] = None
    ml_prediction: str | None = None
    ml_phishing_probability: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    ml_threshold: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    final_decision_confidence: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    rule_ml_agreement: EngineAgreement | None = None
    fusion_reason: str | None = None
    positive_authentication_evidence: list[AuthenticationEvidence] = Field(default_factory=list)
    authentication_evidence: list[AuthenticationEvidence] = Field(default_factory=list)
    authentication_evidence_status: str = 'unavailable'
    analysis_freshness: AnalysisFreshness
    stale_reason: str | None = None
    analysis_completeness_status: AnalysisCompletenessLevel = AnalysisCompletenessLevel.partial
    missing_evidence: list[str] = Field(default_factory=list)
    incomplete_reason_codes: list[str] = Field(default_factory=list)
    decision_safety_status: DecisionSafetyStatus = DecisionSafetyStatus.needs_review
    presentation_state: PresentationState = PresentationState.needs_review
    requires_rescan: bool = False
    safe_verdict_allowed: bool = False
    engines_requested: list[str] = Field(default_factory=lambda: ['rules', 'ml'])
    engines_completed: list[str] = Field(default_factory=list)
    engines_failed: list[str] = Field(default_factory=list)
    decision_source: str = 'unknown'
    fusion_performed: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    fusion_policy_version: str = 'asymmetric-safety-v1'
    fusion_inputs: dict[str, Any] = Field(default_factory=dict)
    fusion_components: list[str] = Field(default_factory=list)
    rule_weight: float = 0.5
    ml_weight: float = 0.5
    safety_floor_applied: bool = False
    safety_floor_rule_id: str | None = None
    applied_floor_reason: str | None = None
    disagreement_resolution: str | None = None
    pre_floor_score: int | None = Field(default=None, ge=0, le=100)
    post_floor_score: int | None = Field(default=None, ge=0, le=100)
    dominant_evidence_source: str = 'balanced'
    evidence_families: list[str] = Field(default_factory=list)
    high_confidence_rule_evidence: bool = False
    protective_evidence: list[str] = Field(default_factory=list)
    current_rule_version: str | None = None
    stored_rule_version: str | None = None
    link_language_present: bool = False
    actual_url_count: int = 0
    html_anchor_count: int = 0
    url_extraction_status: str = 'unavailable'
    url_extraction_reason: str | None = None
    actionable_url_count: int = 0
    tracking_pixel_count: int = 0
    external_tracking_pixel_count: int = 0
    mailto_count: int = 0
    actionable_mailto_count: int = 0
    mailto_destinations_redacted_or_normalized: list[str] = Field(default_factory=list)
    mailto_domain_count: int = 0
    mailto_external_domain_mismatch: bool = False
    mailto_personal_provider: bool = False
    mailto_action_types: list[str] = Field(default_factory=list)
    mailto_action_type: str = 'unknown'
