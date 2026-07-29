from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException

from app.core.logging import log_event
from app.schemas.inference import AnalyzeRequest, PredictionResponse
from app.services.analysis_pipeline import MLUnavailableError, pipeline
from app.services.inference_service import inference_service
from app.services.model_manager import ModelManagerError

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post('/analyze', response_model=PredictionResponse)
def analyze_email(payload: AnalyzeRequest) -> PredictionResponse:
    started = time.perf_counter()
    parser_started = time.perf_counter()
    try:
        unified = pipeline.run(payload.raw_email)
        parser_ms = (time.perf_counter() - parser_started) * 1000
        loaded = inference_service.manager.load_deployment_candidate()
        ml = unified.ml_analysis
        if ml.status.value != 'available' or ml.prediction is None or ml.phishing_probability is None:
            raise MLUnavailableError('Machine-learning analysis is temporarily unavailable.')
        model_signals = inference_service._signals(unified.parser)
        model_families = sorted({
            'lexical',
            *({'url'} if model_signals.url_indicators else set()),
            *({'authentication'} if model_signals.authentication_signals else set()),
            *({'urgency'} if model_signals.urgency_indicators else set()),
        })
        response = PredictionResponse(
            model_id=loaded.record.model_id,
            model_version=ml.model_version or loaded.record.version,
            prediction=ml.prediction,
            probability=ml.phishing_probability,
            # These remain raw model values for backwards-compatible model
            # telemetry. The presentation-safe decision is separate below.
            risk_score=round(ml.phishing_probability * 100),
            confidence=max(ml.phishing_probability, 1.0 - ml.phishing_probability),
            threshold_used=ml.decision_threshold or loaded.record.threshold,
            feature_families=model_families,
            signals=model_signals,
            recommendations=unified.recommendations,
            processing_time_ms=pipeline._last_timings.get('inference_ms', 0.0),
            final_classification=unified.decision.classification.value,
            final_risk_score=unified.decision.risk_score,
            final_decision_confidence=unified.final_decision_confidence,
            rule_findings=unified.rule_analysis.signals,
            analysis_completeness=unified.analysis_completeness,
            analysis_completeness_status=unified.analysis_completeness_status.value,
            analysis_freshness=unified.analysis_freshness.value,
            stale_reason=unified.stale_reason,
            missing_evidence=unified.missing_evidence,
            incomplete_reason_codes=unified.incomplete_reason_codes,
            decision_safety_status=unified.decision_safety_status.value,
            presentation_state=unified.presentation_state.value,
            requires_rescan=unified.requires_rescan,
            safe_verdict_allowed=unified.safe_verdict_allowed,
            engines_requested=unified.engines_requested,
            engines_completed=unified.engines_completed,
            engines_failed=unified.engines_failed,
            decision_source=unified.decision_source,
            fusion_performed=unified.fusion_performed,
            fallback_used=unified.fallback_used,
            fallback_reason=unified.fallback_reason,
            rule_raw_score=unified.rule_raw_score,
            rule_adjusted_score=unified.rule_adjusted_score,
            rule_ml_agreement=unified.rule_ml_agreement.value if unified.rule_ml_agreement else None,
            fusion_reason=unified.fusion_reason,
            authentication_evidence_status=unified.authentication_evidence_status,
            authentication_evidence=[item.model_dump() for item in unified.authentication_evidence],
            positive_authentication_evidence=[item.model_dump() for item in unified.positive_authentication_evidence],
            extracted_urls=unified.parser.extracted_urls,
            url_evidence=[item.model_dump() for item in unified.parser.url_evidence],
            link_language_present=unified.link_language_present,
            actual_url_count=unified.actual_url_count,
            html_anchor_count=unified.html_anchor_count,
            url_extraction_status=unified.url_extraction_status,
            url_extraction_reason=unified.url_extraction_reason,
            current_rule_version=unified.current_rule_version,
            stored_rule_version=unified.stored_rule_version,
            fusion_policy_version=unified.fusion_policy_version,
            fusion_inputs=unified.fusion_inputs,
            fusion_components=unified.fusion_components,
            rule_weight=unified.rule_weight,
            ml_weight=unified.ml_weight,
            safety_floor_applied=unified.safety_floor_applied,
            safety_floor_rule_id=unified.safety_floor_rule_id,
            applied_floor_reason=unified.applied_floor_reason,
            disagreement_resolution=unified.disagreement_resolution,
            pre_floor_score=unified.pre_floor_score,
            post_floor_score=unified.post_floor_score,
            dominant_evidence_source=unified.dominant_evidence_source,
            evidence_families=unified.evidence_families,
            high_confidence_rule_evidence=unified.high_confidence_rule_evidence,
            protective_evidence=unified.protective_evidence,
            actionable_url_count=unified.actionable_url_count,
            tracking_pixel_count=unified.tracking_pixel_count,
            external_tracking_pixel_count=unified.external_tracking_pixel_count,
            mailto_count=unified.mailto_count,
            actionable_mailto_count=unified.actionable_mailto_count,
            mailto_destinations_redacted_or_normalized=unified.mailto_destinations_redacted_or_normalized,
            mailto_domain_count=unified.mailto_domain_count,
            mailto_external_domain_mismatch=unified.mailto_external_domain_mismatch,
            mailto_personal_provider=unified.mailto_personal_provider,
            mailto_action_types=unified.mailto_action_types,
            mailto_action_type=unified.mailto_action_type,
            parser_success=unified.analysis_completeness.parser_success,
            rules_available=unified.analysis_completeness.rules_available,
            ml_available=unified.analysis_completeness.ml_available,
            fusion_available=unified.analysis_completeness.fusion_available,
        )
        log_event(logger, logging.DEBUG, 'analysis.timing',
                  parser_ms=round(parser_ms, 3), rules_ms=0.0,
                  inference_ms=round(response.processing_time_ms, 3),
                  total_ms=round((time.perf_counter() - started) * 1000, 3))
        return response
    except ValueError as error:
        raise HTTPException(status_code=400, detail={"code": "invalid_email", "message": str(error)}) from None
    except (ModelManagerError, MLUnavailableError) as error:
        raise HTTPException(status_code=503, detail={"code": error.code, "message": str(error)}) from None
    except Exception:
        raise HTTPException(status_code=500, detail={"code": "inference_failure", "message": "Inference failed safely."}) from None
