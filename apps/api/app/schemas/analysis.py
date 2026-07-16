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


class DecisionResult(BaseModel):
    classification: ThreatClassification = Field(...)
    risk_score: Annotated[int, Field(ge=0, le=100)] = Field(...)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(...)


class UnifiedAnalysisResponse(BaseModel):
    parser: ParsedEmail = Field(...)
    rule_analysis: AnalysisResult = Field(...)
    ml_analysis: MLAnalysisResult = Field(...)
    decision: DecisionResult = Field(...)
    recommendations: list[str] = Field(default_factory=list)
