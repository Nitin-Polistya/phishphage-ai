"""In-memory parsed-email inference and safe explanations."""

from __future__ import annotations

import re
import time

from app.schemas.email import ParsedEmail
from app.schemas.inference import InferenceSignals, PredictionResponse
from app.services.model_manager import ModelManager
from app.core.settings import get_settings
from app.core.runtime_metrics import runtime_metrics


class InferenceService:
    STARTUP_WARMUP_TEXT = 'Synthetic startup warmup text for model readiness.'

    def __init__(self, manager: ModelManager | None = None):
        settings = get_settings()
        self.manager = manager or ModelManager(
            registry_path=settings.ml_registry_path,
            selected_model_id=settings.ml_model_id,
            artifact_override=settings.ml_artifact_path,
        )

    def prepare(self, warmup_text: str | None = None) -> dict[str, float]:
        """Load and exercise the approved predictor before serving requests."""
        load_started = time.perf_counter()
        loaded = self.manager.load_deployment_candidate()
        load_call_ms = (time.perf_counter() - load_started) * 1000
        warmup_started = time.perf_counter()
        loaded.predictor.predict_proba([warmup_text or self.STARTUP_WARMUP_TEXT])
        warmup_ms = (time.perf_counter() - warmup_started) * 1000
        timings = self.manager.last_timings
        return {
            'model_load_ms': round(max(load_call_ms, timings.get('model_load_ms', 0.0)), 3),
            'artifact_hash_ms': round(timings.get('artifact_hash_ms', 0.0), 3),
            'model_warmup_ms': round(warmup_ms, 3),
        }

    def predict_email(self, parsed: ParsedEmail) -> PredictionResponse:
        started = time.perf_counter_ns()
        text = f"{parsed.subject or ''}\n{parsed.body_text or ''}".strip()
        if not text:
            raise ValueError("Email must contain a subject or body")
        inference_started = time.perf_counter()
        try:
            loaded, probabilities = self.manager.predict(text)
        finally:
            runtime_metrics.record_inference((time.perf_counter() - inference_started) * 1000)
        probability = float(probabilities[1])
        prediction = "phishing" if probability >= loaded.record.threshold else "legitimate"
        indicators = self._signals(parsed)
        families = sorted({"lexical", *(["url"] if indicators.url_indicators else []),
                           *(["authentication"] if indicators.authentication_signals else []),
                           *(["urgency"] if indicators.urgency_indicators else [])})
        recommendations = [
            "Verify requests through an independently opened official channel." if prediction == "phishing"
            else "Remain cautious with links, attachments, and requests for sensitive information."
        ]
        if indicators.authentication_signals:
            recommendations.append("Review authentication results before trusting the sender.")
        if indicators.url_indicators:
            recommendations.append("Inspect the destination without opening the link from the message.")
        confidence = max(probability, 1 - probability)
        return PredictionResponse(
            model_id=loaded.record.model_id, model_version=loaded.record.version,
            prediction=prediction, probability=probability, risk_score=round(probability * 100),
            confidence=float(confidence), threshold_used=loaded.record.threshold,
            feature_families=families, signals=indicators, recommendations=recommendations,
            processing_time_ms=(time.perf_counter_ns() - started) / 1_000_000,
        )

    @staticmethod
    def _signals(parsed: ParsedEmail) -> InferenceSignals:
        text = " ".join(filter(None, [parsed.subject, parsed.body_text, parsed.body_visible_text])).lower()
        urls = list(parsed.extracted_urls)
        url_indicators = ["actionable_url" for _ in urls]
        if any(link.domain_mismatch for link in parsed.html_links):
            url_indicators.append("display_destination_mismatch")
        auth_text = " ".join(f"{key}:{value}" for key, value in parsed.headers.items()).lower()
        auth = [name for name, pattern in (("spf", r"spf="), ("dkim", r"dkim="), ("dmarc", r"dmarc=")) if re.search(pattern, auth_text)]
        urgency = [term for term in ("urgent", "immediately", "expire", "suspend", "verify") if re.search(rf"\b{term}\b", text)]
        phishing = [term for term in ("password", "credential", "login", "payment", "invoice", "click", "account") if re.search(rf"\b{term}\b", text)]
        detected = sorted(set(url_indicators + auth + urgency + phishing))
        return InferenceSignals(detected_indicators=detected, phishing_signals=phishing,
                                authentication_signals=auth, url_indicators=url_indicators,
                                urgency_indicators=urgency)


inference_service = InferenceService()
