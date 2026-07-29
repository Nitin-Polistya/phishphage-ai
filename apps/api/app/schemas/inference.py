"""Privacy-safe production inference response models."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.schemas.analysis import AnalysisCompleteness, AnalysisResult, DecisionResult, ThreatSignal


class AnalyzeRequest(BaseModel):
    raw_email: str = Field(..., min_length=1, max_length=2_000_000)


class InferenceSignals(BaseModel):
    detected_indicators: list[str] = Field(default_factory=list)
    phishing_signals: list[str] = Field(default_factory=list)
    authentication_signals: list[str] = Field(default_factory=list)
    url_indicators: list[str] = Field(default_factory=list)
    urgency_indicators: list[str] = Field(default_factory=list)


class PredictionResponse(BaseModel):
    model_id: str
    model_version: str
    prediction: str
    probability: Annotated[float, Field(ge=0.0, le=1.0)]
    risk_score: Annotated[int, Field(ge=0, le=100)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    threshold_used: Annotated[float, Field(ge=0.0, le=1.0)]
    feature_families: list[str] = Field(default_factory=list)
    signals: InferenceSignals
    recommendations: list[str] = Field(default_factory=list)
    processing_time_ms: Annotated[float, Field(ge=0.0)]
    # The ML fields above remain the raw, approved-model output. These fields
    # describe the presentation-safe combined decision and never alter the ML
    # probability, threshold, calibration, or artifact identity.
    final_classification: str | None = None
    final_risk_score: Annotated[int | None, Field(ge=0, le=100)] = None
    final_decision_confidence: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    rule_analysis: AnalysisResult | None = None
    rule_findings: list[ThreatSignal] = Field(default_factory=list)
    decision: DecisionResult | None = None
    analysis_completeness: AnalysisCompleteness | None = None
    analysis_completeness_status: str = 'unavailable'
    analysis_freshness: str = 'stale'
    stale_reason: str | None = None
    missing_evidence: list[str] = Field(default_factory=list)
    incomplete_reason_codes: list[str] = Field(default_factory=list)
    decision_safety_status: str = 'needs_review'
    presentation_state: str = 'needs_review'
    requires_rescan: bool = True
    safe_verdict_allowed: bool = False
    engines_requested: list[str] = Field(default_factory=lambda: ['rules', 'ml'])
    engines_completed: list[str] = Field(default_factory=list)
    engines_failed: list[str] = Field(default_factory=list)
    decision_source: str = 'unknown'
    fusion_performed: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    rule_raw_score: Annotated[int | None, Field(ge=0, le=100)] = None
    rule_adjusted_score: Annotated[int | None, Field(ge=0, le=100)] = None
    rule_ml_agreement: str | None = None
    fusion_reason: str | None = None
    authentication_evidence_status: str = 'unavailable'
    positive_authentication_evidence: list[dict[str, object]] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    url_evidence: list[dict[str, object]] = Field(default_factory=list)
    link_language_present: bool = False
    actual_url_count: int = 0
    html_anchor_count: int = 0
    url_extraction_status: str = 'unavailable'
    url_extraction_reason: str | None = None
    current_rule_version: str | None = None
    stored_rule_version: str | None = None
    parser_success: bool = True
    rules_available: bool = False
    ml_available: bool = False
    fusion_available: bool = False
    fusion_policy_version: str = 'asymmetric-safety-v1'
    fusion_inputs: dict[str, Any] = Field(default_factory=dict)
    fusion_components: list[str] = Field(default_factory=list)
    rule_weight: float = 0.5
    ml_weight: float = 0.5
    safety_floor_applied: bool = False
    safety_floor_rule_id: str | None = None
    applied_floor_reason: str | None = None
    disagreement_resolution: str | None = None
    pre_floor_score: Annotated[int | None, Field(ge=0, le=100)] = None
    post_floor_score: Annotated[int | None, Field(ge=0, le=100)] = None
    dominant_evidence_source: str = 'balanced'
    evidence_families: list[str] = Field(default_factory=list)
    high_confidence_rule_evidence: bool = False
    protective_evidence: list[str] = Field(default_factory=list)
    authentication_evidence: list[dict[str, object]] = Field(default_factory=list)
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
