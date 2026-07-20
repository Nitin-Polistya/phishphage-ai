"""Privacy-safe production inference response models."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field


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
