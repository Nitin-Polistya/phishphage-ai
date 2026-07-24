"""Pydantic schemas for rule-based analysis results."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

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


class EngineAgreement(str, Enum):
    agreement = 'agreement'
    disagreement = 'disagreement'
    ml_unavailable = 'ml_unavailable'


class AnalysisFreshness(str, Enum):
    current = 'current'
    stale = 'stale'


class AuthenticationState(str, Enum):
    passed = 'pass'
    failed = 'fail'
    inconclusive = 'inconclusive'
    missing = 'missing'


class AuthenticationEvidence(BaseModel):
    mechanism: str
    state: AuthenticationState
    domain: str | None = None
    aligned_with_from: bool | None = None


class DecisionResult(BaseModel):
    classification: ThreatClassification = Field(...)
    risk_score: Annotated[int, Field(ge=0, le=100)] = Field(...)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(...)
    fusion_reason: str | None = None
    limited_authentication_evidence: bool = False


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
    authentication_evidence_status: str = 'unavailable'
    analysis_freshness: AnalysisFreshness
    stale_reason: str | None = None
