"""Unified analysis pipeline orchestrating parser, rules, and ML."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from phishshield_ml.inference import LocalInferenceService

# Ensure ML source is in path
# Path(__file__) is apps/api/app/services/analysis_pipeline.py
# parents[0]: services, [1]: app, [2]: api, [3]: apps, [4]: project_root
ML_SRC_PATH = str(Path(__file__).resolve().parents[4] / "services" / "ml" / "src")
if ML_SRC_PATH not in sys.path:
    sys.path.insert(0, ML_SRC_PATH)

# Runtime import handled after sys.path modification
from phishshield_ml.inference import LocalInferenceService
from app.core.settings import get_settings
from app.core.runtime_metrics import runtime_metrics
from app.core.logging import log_event
from app.services.model_manager import APPROVED_ARTIFACT_ROOT, ModelManager
from app.services.email_parser import MAX_EMAIL_SIZE_BYTES, classify_url_extraction, extract_urls, normalize_defanged_indicator, parse_email, parse_email_address, validate_rfc822_source
from app.analyzers.header_analyzer import evaluate_authentication
from app.services.phishing_analyzer import analyze_parsed_email, normalize_recommendations
from app.services.decision_engine import fuse_analysis_results
from app.services.decision_safety import assess_decision_safety
from app.services.safety_fusion import FUSION_POLICY_VERSION
from app.schemas.analysis import (
    AnalysisCompleteness,
    AnalysisCompletenessLevel,
    AnalysisCompletenessState,
    AnalysisFreshness,
    DecisionSafetyStatus,
    EngineAgreement,
    PresentationState,
    UnifiedAnalysisResponse,
    MLAnalysisResult,
)
from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest, EmailUrlEvidence, ParsedEmail, UrlSourceType
from app.services.risk_scoring import calculate_raw_risk_score
from app.services.domain_utils import domains_align

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
ML_UNAVAILABLE_REASON = "Machine-learning analysis is unavailable."
CURRENT_RULE_VERSION = 'rules-v3.1.0'
CURRENT_MODEL_VERSION = '1.0.0'
LIMITED_AUTH_WARNING = (
    'Limited authentication evidence: SPF, DKIM, and DMARC results were unavailable, '
    'and a marginal ML alert had no corroborating malicious rule evidence.'
)
SENSITIVE_ACTION_RECOMMENDATION = (
    'If the message requests a sensitive action, open the official service independently rather than using the email link.'
)
SAFETY_RECOMMENDATIONS = (
    'Do not click links in the message or provide credentials, payment details, or security codes.',
    'Open the claimed service directly using a trusted bookmark or a manually typed official address.',
    'Verify the sender through an independent channel and re-scan the original email after obtaining fresh source data.',
)


class MLUnavailableError(RuntimeError):
    """Raised when ML is configured as required but cannot be used."""

class AnalysisPipeline:
    STARTUP_WARMUP_TEXT = 'Synthetic startup warmup text for analysis adapter readiness.'

    def __init__(
        self,
        model_path: str | Path | None = None,
        ml_required: bool | None = None,
        manager: ModelManager | None = None,
    ):
        settings = get_settings()
        self.model_path = self._resolve_path(model_path) if model_path else None
        configured_override = self.model_path
        if configured_override:
            try:
                configured_override.resolve(strict=False).relative_to(APPROVED_ARTIFACT_ROOT)
            except ValueError:
                # Keep the pipeline safely unavailable; never make an external path loadable.
                configured_override = APPROVED_ARTIFACT_ROOT / '__invalid_external_override__'
        self.model_manager = manager or ModelManager(
            registry_path=settings.ml_registry_path,
            selected_model_id=settings.ml_model_id,
            artifact_override=configured_override,
        )
        self._default_artifact_override = self.model_manager.artifact_override
        self.model_manager.artifact_override = self.model_path or self._default_artifact_override
        self.ml_required = settings.ml_required if ml_required is None else ml_required
        self.ml_marginal_alert_band = settings.ml_marginal_alert_band
        self._ml_service: LocalInferenceService | None = None
        self._last_timings: dict[str, float] = {}

    @property
    def inference_ready(self) -> bool:
        return self._ml_service is not None

    def clear_loaded_state(self) -> None:
        self._ml_service = None

    @property
    def model_path(self) -> Path | None:
        return self._model_path

    @model_path.setter
    def model_path(self, value: str | Path | None) -> None:
        self._model_path = value
        if hasattr(self, 'model_manager') and hasattr(self, '_default_artifact_override'):
            self.model_manager.artifact_override = value or self._default_artifact_override

    def prepare(self, warmup_text: str | None = None) -> dict[str, float]:
        """Construct the adapter and run one privacy-safe synthetic prediction."""
        adapter_started = time.perf_counter()
        ml_service = self._get_ml_service()
        adapter_construction_ms = (time.perf_counter() - adapter_started) * 1000
        warmup_started = time.perf_counter()
        ml_service.predict(warmup_text or self.STARTUP_WARMUP_TEXT)
        warmup_ms = (time.perf_counter() - warmup_started) * 1000
        return {
            'adapter_construction_ms': round(adapter_construction_ms, 3),
            'model_warmup_ms': round(warmup_ms, 3),
        }

    def _get_ml_service(self) -> LocalInferenceService:
        """Lazy load the ML service."""
        if self._ml_service is None:
            try:
                # ModelManager is the sole authority for candidate selection and
                # verifies every artifact hash before any inference object sees it.
                self.model_manager.artifact_override = self.model_path or self._default_artifact_override
                loaded = self.model_manager.load_deployment_candidate()
                self._ml_service = LocalInferenceService(loaded.record.artifact_path, verified_model=loaded)
            except Exception:
                raise MLUnavailableError(ML_UNAVAILABLE_REASON) from None
        return self._ml_service

    def _publish_analysis_timing(
        self,
        started: float,
        parser_ms: float,
        rules_ms: float,
        inference_ms: float,
    ) -> None:
        fields = {
            'parser_ms': round(max(0.0, parser_ms), 3),
            'rules_ms': round(max(0.0, rules_ms), 3),
            'inference_ms': round(max(0.0, inference_ms), 3),
            'total_ms': round(max(0.0, (time.perf_counter() - started) * 1000), 3),
        }
        self._last_timings = fields
        log_event(logger, logging.DEBUG, 'analysis.timing', **fields)

    @staticmethod
    def _resolve_path(path: str | Path) -> Path:
        candidate = Path(path)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate

    def run(self, raw_email: str) -> UnifiedAnalysisResponse:
        """
        Executes the full analysis pipeline:
        Parse -> Rule-Based Analysis -> ML Inference -> Decision Fusion
        """
        # Step 1: Parse raw email
        # parse_email raises ValueError for invalid input
        request = AnalysisPreviewRequest(input_mode=AnalysisInputMode.raw_email, raw_email=raw_email)
        return self.run_request(request)

    def run_request(self, request: AnalysisPreviewRequest) -> UnifiedAnalysisResponse:
        """Execute one normalized analysis path for every supported input mode."""
        started = time.perf_counter()
        parser_started = time.perf_counter()
        if request.input_mode == AnalysisInputMode.quick_paste:
            size = len((request.body or '').encode('utf-8'))
            if size > MAX_EMAIL_SIZE_BYTES:
                raise ValueError(f'Email exceeds maximum size of {MAX_EMAIL_SIZE_BYTES} bytes')
            sender_value = str(request.sender_email) if request.sender_email else None
            if sender_value and request.sender_name:
                sender_value = f'{request.sender_name} <{sender_value}>'
            recipient_value = str(request.recipient_email) if request.recipient_email else None
            if recipient_value and request.recipient_name:
                recipient_value = f'{request.recipient_name} <{recipient_value}>'
            quick_text = f'{request.subject or ""}\n{request.body or ""}'
            quick_urls = extract_urls(quick_text)
            quick_link_language, quick_url_count, quick_anchor_count, quick_url_status, quick_url_reason = classify_url_extraction(
                subject=request.subject,
                body_text=request.body or '',
                body_html=None,
                urls=quick_urls,
                html_links=[],
            )
            parsed_email = ParsedEmail(
                subject=request.subject,
                sender=parse_email_address(sender_value),
                reply_to=parse_email_address(str(request.reply_to)) if request.reply_to else None,
                recipients=[parsed for parsed in [parse_email_address(recipient_value)] if parsed] if recipient_value else [],
                body_text=request.body or '',
                extracted_urls=quick_urls,
                url_evidence=[
                    EmailUrlEvidence(url=url, source_type=UrlSourceType.plain_text, user_actionable=True)
                    for url in quick_urls
                ],
                link_language_present=quick_link_language,
                actual_url_count=quick_url_count,
                html_anchor_count=quick_anchor_count,
                url_extraction_status=quick_url_status,
                url_extraction_reason=quick_url_reason,
                attachments=request.attachments,
            )
        else:
            try:
                validate_rfc822_source(request.raw_email or '')
            except ValueError as error:
                if request.input_mode == AnalysisInputMode.eml_upload:
                    raise ValueError('The .eml file does not contain a valid RFC822 message structure.') from None
                raise error
            parsed_email = parse_email(request.raw_email or '')

        parser_ms = (time.perf_counter() - parser_started) * 1000

        rules_started = time.perf_counter()
        completeness = self._analysis_completeness(request, parsed_email)
        authentication = evaluate_authentication(
            parsed_email.headers,
            str(parsed_email.sender.address) if parsed_email.sender else None,
        )
        positive_authentication = [
            item for item in authentication.evidence if item.state.value == 'pass'
        ]
        authentication_status = self._authentication_evidence_status(authentication.evidence)
        
        # Step 2: Run rule-based analyzer
        rule_result = analyze_parsed_email(parsed_email, input_mode=request.input_mode)
        parsed_email = parsed_email.model_copy(update={
            'mailto_external_domain_mismatch': any(
                signal.code == 'mailto_destination_mismatch' for signal in rule_result.signals
            ),
        })
        rules_ms = (time.perf_counter() - rules_started) * 1000
        
        # Step 3: Run ML inference
        ml_result: MLAnalysisResult
        inference_ms = 0.0
        try:
            ml_service = self._get_ml_service()
            # Combine subject and body for ML analysis
            text_for_ml = f"{parsed_email.subject or ''}\n{parsed_email.body_text}"
            inference_started = time.perf_counter()
            try:
                inference = ml_service.predict(text_for_ml)
            finally:
                inference_ms = (time.perf_counter() - inference_started) * 1000
                runtime_metrics.record_inference(inference_ms)
            
            ml_result = MLAnalysisResult(
                status='available',
                prediction=str(inference.predicted_label),
                phishing_probability=float(inference.phishing_probability),
                legitimate_probability=float(inference.legitimate_probability),
                model_version=str(ml_service.model_version),
                reason=None,
                decision_threshold=float(ml_service.decision_threshold),
            )
        except Exception:
            log_event(logger, logging.WARNING, 'model.inference_unavailable',
                      reason_code='model_unavailable', fallback_allowed=not self.ml_required)
            if self.ml_required:
                raise MLUnavailableError(ML_UNAVAILABLE_REASON)
            ml_result = MLAnalysisResult(
                status='unavailable',
                prediction=None,
                phishing_probability=None,
                legitimate_probability=None,
                model_version=None,
                reason=ML_UNAVAILABLE_REASON,
                decision_threshold=None,
            )
            fallback_decision = {
                'classification': rule_result.classification,
                'risk_score': rule_result.risk_score,
                'confidence': rule_result.confidence,
                'decision_source': 'rules_fallback',
                'fusion_performed': False,
                'fallback_used': True,
                'fallback_reason': ML_UNAVAILABLE_REASON,
            }
            if completeness.limited_evidence and str(rule_result.classification.value) == 'safe':
                fallback_decision['confidence'] = min(float(rule_result.confidence), 0.65)
            safety = assess_decision_safety(
                parser_success=True,
                rule_available=True,
                ml_available=False,
                fusion_performed=False,
                freshness='stale',
                stale_reason=ML_UNAVAILABLE_REASON,
                parsed=parsed_email,
                rule_result=rule_result,
                input_evidence_complete=not completeness.limited_evidence,
            )
            response_completeness = completeness.model_copy(update={
                'analysis_state': safety.analysis_state,
                'missing_evidence': list(dict.fromkeys([*completeness.missing_evidence, *safety.missing_evidence])),
                'incomplete_reason_codes': safety.reason_codes,
                'rules_available': True,
                'ml_available': False,
                'fusion_available': False,
            })
            recommendations = normalize_recommendations([*SAFETY_RECOMMENDATIONS, *rule_result.recommendations])
            self._publish_analysis_timing(started, parser_ms, rules_ms, inference_ms)
            return UnifiedAnalysisResponse(
                parser=parsed_email,
                rule_analysis=rule_result,
                ml_analysis=ml_result,
                decision=fallback_decision,
                recommendations=recommendations,
                analysis_completeness=response_completeness,
                engine_agreement=EngineAgreement.ml_unavailable,
                rule_raw_score=calculate_raw_risk_score(rule_result.signals),
                rule_adjusted_score=rule_result.risk_score,
                ml_prediction=None,
                ml_phishing_probability=None,
                ml_threshold=None,
                final_decision_confidence=fallback_decision['confidence'],
                rule_ml_agreement=None,
                fusion_reason=None,
                positive_authentication_evidence=positive_authentication,
                authentication_evidence=list(authentication.evidence),
                authentication_evidence_status=authentication_status,
                analysis_freshness=AnalysisFreshness.stale,
                stale_reason=ML_UNAVAILABLE_REASON,
                analysis_completeness_status=safety.analysis_state,
                missing_evidence=response_completeness.missing_evidence,
                incomplete_reason_codes=safety.reason_codes,
                decision_safety_status=safety.status,
                presentation_state=safety.presentation_state,
                requires_rescan=safety.requires_rescan,
                safe_verdict_allowed=False,
                engines_completed=['rules'],
                engines_failed=['ml', 'fusion'],
                decision_source='rules_fallback',
                fusion_performed=False,
                fallback_used=True,
                fallback_reason=ML_UNAVAILABLE_REASON,
                current_rule_version=CURRENT_RULE_VERSION,
                stored_rule_version=rule_result.engine_version,
                link_language_present=parsed_email.link_language_present,
                actual_url_count=parsed_email.actual_url_count,
                html_anchor_count=parsed_email.html_anchor_count,
                url_extraction_status=parsed_email.url_extraction_status,
                url_extraction_reason=parsed_email.url_extraction_reason,
                fusion_policy_version=FUSION_POLICY_VERSION,
                fusion_components=['rules_only_fallback'],
                dominant_evidence_source='rules',
                pre_floor_score=None,
                post_floor_score=rule_result.risk_score,
                evidence_families=[],
                high_confidence_rule_evidence=False,
                protective_evidence=[],
                actionable_url_count=parsed_email.actionable_url_count,
                tracking_pixel_count=parsed_email.tracking_pixel_count,
                external_tracking_pixel_count=parsed_email.external_tracking_pixel_count,
                mailto_count=parsed_email.mailto_count,
                actionable_mailto_count=parsed_email.actionable_mailto_count,
                mailto_destinations_redacted_or_normalized=parsed_email.mailto_destinations_redacted_or_normalized,
                mailto_domain_count=parsed_email.mailto_domain_count,
                mailto_external_domain_mismatch=parsed_email.mailto_external_domain_mismatch,
                mailto_personal_provider=parsed_email.mailto_personal_provider,
                mailto_action_types=parsed_email.mailto_action_types,
                mailto_action_type=parsed_email.mailto_action_type,
            )

        # Step 4: Final Decision Fusion
        if ml_result.prediction is None or ml_result.phishing_probability is None:
            raise RuntimeError('Available ML analysis did not produce a prediction')
        strong_malicious_evidence = any(
            signal.severity.value == 'high' and signal.score > 0 for signal in rule_result.signals
        )
        marginal_alert_eligible = self._marginal_alert_eligible(parsed_email, rule_result)
        decision = fuse_analysis_results(
            rule_result=rule_result,
            ml_prediction=ml_result.prediction,
            ml_probability=ml_result.phishing_probability,
            authenticated_sender=authentication.trusted_sender,
            strong_malicious_evidence=strong_malicious_evidence,
            ml_threshold=ml_result.decision_threshold or 0.5,
            marginal_alert_band=self.ml_marginal_alert_band,
            marginal_alert_eligible=marginal_alert_eligible,
            parsed_email=parsed_email,
        )
        if completeness.limited_evidence and str(decision.classification.value) == 'safe':
            decision = decision.model_copy(update={'confidence': min(decision.confidence, 0.65)})
        rule_suspicious = str(rule_result.classification.value) != 'safe'
        ml_suspicious = ml_result.prediction == 'phishing'
        agreement = EngineAgreement.agreement if rule_suspicious == ml_suspicious else EngineAgreement.disagreement
        freshness, stale_reason = self._engine_freshness(
            rule_result.engine_version, ml_result.status.value, ml_result.model_version
        )
        safety = assess_decision_safety(
            parser_success=True,
            rule_available=True,
            ml_available=True,
            fusion_performed=True,
            freshness=freshness.value,
            stale_reason=stale_reason,
            parsed=parsed_email,
            rule_result=rule_result,
            input_evidence_complete=not completeness.limited_evidence,
        )
        # Quick Paste and partial source remain valid analyses, but their input
        # evidence is explicitly marked partial rather than promoted to full.
        completeness_status = safety.analysis_state
        if completeness.limited_evidence and completeness_status == AnalysisCompletenessLevel.complete:
            completeness_status = AnalysisCompletenessLevel.partial
        response_completeness = completeness.model_copy(update={
            'analysis_state': completeness_status,
            'missing_evidence': list(dict.fromkeys([*completeness.missing_evidence, *safety.missing_evidence])),
            'incomplete_reason_codes': safety.reason_codes,
            'rules_available': True,
            'ml_available': True,
            'fusion_available': True,
        })
        recommendations = normalize_recommendations(list(rule_result.recommendations))
        if decision.limited_authentication_evidence:
            response_completeness = response_completeness.model_copy(update={
                'limited_evidence': True,
                'warning': LIMITED_AUTH_WARNING,
            })
            recommendations = normalize_recommendations([*recommendations, SENSITIVE_ACTION_RECOMMENDATION])
        if safety.status != DecisionSafetyStatus.eligible or not safety.safe_verdict_allowed:
            recommendations = normalize_recommendations([*SAFETY_RECOMMENDATIONS, *recommendations])
        safe_allowed = safety.safe_verdict_allowed and decision.classification == 'safe'
        if freshness == AnalysisFreshness.stale:
            presentation_state = PresentationState.rescan_required
        elif not safe_allowed and decision.classification == 'safe':
            presentation_state = PresentationState.needs_review
        else:
            presentation_state = PresentationState(str(decision.classification.value))
        decision = decision.model_copy(update={
            'decision_source': 'rule_ml_fusion',
            'fusion_performed': True,
            'fallback_used': False,
            'fallback_reason': None,
        })
        
        # Step 5: Generate unified response
        self._publish_analysis_timing(started, parser_ms, rules_ms, inference_ms)
        return UnifiedAnalysisResponse(
            parser=parsed_email,
            rule_analysis=rule_result,
            ml_analysis=ml_result,
            decision=decision,
            recommendations=recommendations,
            analysis_completeness=response_completeness,
            engine_agreement=agreement,
            rule_raw_score=calculate_raw_risk_score(rule_result.signals),
            rule_adjusted_score=rule_result.risk_score,
            ml_prediction=ml_result.prediction,
            ml_phishing_probability=ml_result.phishing_probability,
            ml_threshold=ml_result.decision_threshold,
            final_decision_confidence=decision.confidence if safe_allowed or decision.classification != 'safe' else min(decision.confidence, 0.5),
            rule_ml_agreement=agreement,
            fusion_reason=decision.fusion_reason,
            positive_authentication_evidence=positive_authentication,
            authentication_evidence=list(authentication.evidence),
            authentication_evidence_status=authentication_status,
            analysis_freshness=freshness,
            stale_reason=stale_reason,
            analysis_completeness_status=completeness_status,
            missing_evidence=response_completeness.missing_evidence,
            incomplete_reason_codes=safety.reason_codes,
            decision_safety_status=safety.status,
            presentation_state=presentation_state,
            requires_rescan=safety.requires_rescan,
            safe_verdict_allowed=safe_allowed,
            engines_completed=['rules', 'ml', 'fusion'],
            engines_failed=[],
            decision_source='rule_ml_fusion',
            fusion_performed=True,
            fallback_used=False,
            fallback_reason=None,
            current_rule_version=CURRENT_RULE_VERSION,
            stored_rule_version=rule_result.engine_version,
            link_language_present=parsed_email.link_language_present,
            actual_url_count=parsed_email.actual_url_count,
            html_anchor_count=parsed_email.html_anchor_count,
            url_extraction_status=parsed_email.url_extraction_status,
            url_extraction_reason=parsed_email.url_extraction_reason,
            fusion_policy_version=decision.fusion_policy_version,
            fusion_inputs=decision.fusion_inputs,
            fusion_components=decision.fusion_components,
            rule_weight=decision.rule_weight,
            ml_weight=decision.ml_weight,
            safety_floor_applied=decision.safety_floor_applied,
            safety_floor_rule_id=decision.safety_floor_rule_id,
            applied_floor_reason=decision.applied_floor_reason,
            disagreement_resolution=decision.disagreement_resolution,
            pre_floor_score=decision.pre_floor_score,
            post_floor_score=decision.post_floor_score,
            dominant_evidence_source=decision.dominant_evidence_source,
            evidence_families=decision.evidence_families,
            high_confidence_rule_evidence=decision.high_confidence_rule_evidence,
            protective_evidence=decision.protective_evidence,
            actionable_url_count=parsed_email.actionable_url_count,
            tracking_pixel_count=parsed_email.tracking_pixel_count,
            external_tracking_pixel_count=parsed_email.external_tracking_pixel_count,
            mailto_count=parsed_email.mailto_count,
            actionable_mailto_count=parsed_email.actionable_mailto_count,
            mailto_destinations_redacted_or_normalized=parsed_email.mailto_destinations_redacted_or_normalized,
            mailto_domain_count=parsed_email.mailto_domain_count,
            mailto_external_domain_mismatch=parsed_email.mailto_external_domain_mismatch,
            mailto_personal_provider=parsed_email.mailto_personal_provider,
            mailto_action_types=parsed_email.mailto_action_types,
            mailto_action_type=parsed_email.mailto_action_type,
        )

    @staticmethod
    def _authentication_evidence_status(evidence) -> str:
        states = {item.state.value for item in evidence}
        if 'fail' in states:
            return 'failed'
        if 'pass' in states:
            return 'available'
        if 'inconclusive' in states:
            return 'inconclusive'
        return 'unavailable'

    @staticmethod
    def _marginal_alert_eligible(parsed_email: ParsedEmail, rule_result) -> bool:
        positive_signals = [signal for signal in rule_result.signals if signal.score > 0]
        if rule_result.risk_score > 8 or {signal.code for signal in positive_signals} != {'header_missing_authentication'}:
            return False
        if any(signal.severity.value in {'medium', 'high'} for signal in positive_signals):
            return False
        if any(link.domain_mismatch for link in parsed_email.html_links):
            return False
        if not parsed_email.sender:
            return False
        sender_domain = str(parsed_email.sender.address).rsplit('@', 1)[-1]
        for evidence in parsed_email.url_evidence:
            if not evidence.user_actionable:
                continue
            hostname = urlparse(normalize_defanged_indicator(evidence.url)).hostname
            if not hostname or not domains_align(sender_domain, hostname):
                return False
        return True

    @staticmethod
    def _engine_freshness(rule_version: str, ml_status: str, model_version: str | None):
        if rule_version != CURRENT_RULE_VERSION:
            return AnalysisFreshness.stale, f'Expected rule engine {CURRENT_RULE_VERSION}; received {rule_version}.'
        if ml_status != 'available':
            return AnalysisFreshness.stale, ML_UNAVAILABLE_REASON
        if model_version != CURRENT_MODEL_VERSION:
            return AnalysisFreshness.stale, f'Expected ML model {CURRENT_MODEL_VERSION}; received {model_version or "none"}.'
        return AnalysisFreshness.current, None

    @staticmethod
    def _analysis_completeness(request: AnalysisPreviewRequest, parsed_email: ParsedEmail) -> AnalysisCompleteness:
        headers = {key.lower(): value for key, value in parsed_email.headers.items()}
        authentication = headers.get('authentication-results', '')
        has_auth = bool(authentication or headers.get('received-spf'))
        has_spf = 'spf=' in authentication.lower() or bool(headers.get('received-spf'))
        has_dkim = 'dkim=' in authentication.lower()
        has_dmarc = 'dmarc=' in authentication.lower()
        is_raw = request.input_mode in {AnalysisInputMode.raw_email, AnalysisInputMode.eml_upload}
        complete_headers = bool(
            is_raw and parsed_email.sender and headers.get('date') and headers.get('message-id')
            and (headers.get('return-path') or authentication or headers.get('received'))
        )
        has_structured = bool(parsed_email.sender or parsed_email.reply_to or parsed_email.recipients or parsed_email.attachments)
        if complete_headers:
            state = AnalysisCompletenessState.complete_raw_email
            warning = None
        elif parsed_email.body_html:
            state = AnalysisCompletenessState.html_content
            warning = 'Limited evidence: HTML destinations were available, but complete transport and authentication headers were not.'
        elif has_structured:
            state = AnalysisCompletenessState.structured_fields
            warning = 'Limited evidence: some structured fields were available, but complete raw headers and HTML destinations were not.'
        else:
            state = AnalysisCompletenessState.body_text_only
            warning = 'Limited evidence: only subject/body text was available. Sender authentication, real HTML destinations, and transport headers were not analyzed.'
        missing_evidence: list[str] = []
        if not parsed_email.sender:
            missing_evidence.append('sender identity')
        if not has_auth:
            missing_evidence.append('authentication status')
        if parsed_email.link_language_present and not parsed_email.extracted_urls:
            missing_evidence.append('verifiable link destination')
        if not parsed_email.body_html:
            missing_evidence.append('HTML anchor destinations')
        if not complete_headers:
            missing_evidence.append('complete transport headers')
        return AnalysisCompleteness(
            state=state,
            limited_evidence=state != AnalysisCompletenessState.complete_raw_email,
            warning=warning,
            has_from_header=bool(is_raw and parsed_email.sender),
            has_reply_to=bool(parsed_email.reply_to),
            has_return_path=bool(headers.get('return-path')),
            has_authentication_results=has_auth,
            has_spf_result=has_spf,
            has_dkim_result=has_dkim,
            has_dmarc_result=has_dmarc,
            has_html_source=bool(parsed_email.body_html),
            has_real_href_destinations=bool(parsed_email.html_links),
            has_attachment_metadata=is_raw or bool(parsed_email.attachments),
            has_complete_raw_headers=complete_headers,
            analysis_state=AnalysisCompletenessLevel.partial if state != AnalysisCompletenessState.complete_raw_email else AnalysisCompletenessLevel.partial,
            missing_evidence=list(dict.fromkeys(missing_evidence)),
            parser_success=True,
        )

    @staticmethod
    def _qualify_safe_warning(completeness: AnalysisCompleteness, is_safe: bool) -> AnalysisCompleteness:
        if not completeness.warning:
            return completeness
        return completeness.model_copy(update={
            'warning': completeness.warning.replace('Safe based on limited evidence:', 'Limited evidence:')
        })

# Singleton instance for the API. Both supported analysis endpoints share the
# same verified ModelManager cache, so startup preparation covers both paths.
from app.services.inference_service import inference_service

pipeline = AnalysisPipeline(manager=inference_service.manager)
