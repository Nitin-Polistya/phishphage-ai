"""Unified analysis pipeline orchestrating parser, rules, and ML."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

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
from app.services.email_parser import MAX_EMAIL_SIZE_BYTES, extract_urls, parse_email, parse_email_address, validate_rfc822_source
from app.analyzers.header_analyzer import evaluate_authentication
from app.services.phishing_analyzer import analyze_parsed_email
from app.services.decision_engine import fuse_analysis_results
from app.schemas.analysis import (
    AnalysisCompleteness,
    AnalysisCompletenessState,
    EngineAgreement,
    UnifiedAnalysisResponse,
    MLAnalysisResult,
)
from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest, EmailUrlEvidence, ParsedEmail, UrlSourceType
from app.services.risk_scoring import calculate_raw_risk_score

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
ML_UNAVAILABLE_REASON = "Machine-learning analysis is unavailable."


class MLUnavailableError(RuntimeError):
    """Raised when ML is configured as required but cannot be used."""

class AnalysisPipeline:
    def __init__(self, model_path: str | Path | None = None, ml_required: bool | None = None):
        settings = get_settings()
        configured_path = Path(model_path or settings.ml_model_path)
        self.model_path = configured_path if configured_path.is_absolute() else PROJECT_ROOT / configured_path
        self.ml_required = settings.ml_required if ml_required is None else ml_required
        self._ml_service: LocalInferenceService | None = None

    def _get_ml_service(self) -> LocalInferenceService:
        """Lazy load the ML service."""
        if self._ml_service is None:
            try:
                self._ml_service = LocalInferenceService(self.model_path)
            except Exception:
                raise MLUnavailableError(ML_UNAVAILABLE_REASON) from None
        return self._ml_service

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
            parsed_email = ParsedEmail(
                subject=request.subject,
                sender=parse_email_address(sender_value),
                reply_to=parse_email_address(str(request.reply_to)) if request.reply_to else None,
                recipients=[parsed for parsed in [parse_email_address(recipient_value)] if parsed] if recipient_value else [],
                body_text=request.body or '',
                extracted_urls=extract_urls(f'{request.subject or ""}\n{request.body or ""}'),
                url_evidence=[
                    EmailUrlEvidence(url=url, source_type=UrlSourceType.plain_text, user_actionable=True)
                    for url in extract_urls(f'{request.subject or ""}\n{request.body or ""}')
                ],
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

        completeness = self._analysis_completeness(request, parsed_email)
        authentication = evaluate_authentication(
            parsed_email.headers,
            str(parsed_email.sender.address) if parsed_email.sender else None,
        )
        positive_authentication = [
            item for item in authentication.evidence if item.state.value == 'pass'
        ]
        
        # Step 2: Run rule-based analyzer
        rule_result = analyze_parsed_email(parsed_email, input_mode=request.input_mode)
        
        # Step 3: Run ML inference
        ml_result: MLAnalysisResult
        try:
            ml_service = self._get_ml_service()
            # Combine subject and body for ML analysis
            text_for_ml = f"{parsed_email.subject or ''}\n{parsed_email.body_text}"
            inference = ml_service.predict(text_for_ml)
            
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
            logger.warning("ML analysis is unavailable; applying configured availability policy")
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
            }
            if completeness.limited_evidence and str(rule_result.classification.value) == 'safe':
                fallback_decision['confidence'] = min(float(rule_result.confidence), 0.65)
            response_completeness = self._qualify_safe_warning(
                completeness, str(rule_result.classification.value) == 'safe'
            )
            return UnifiedAnalysisResponse(
                parser=parsed_email,
                rule_analysis=rule_result,
                ml_analysis=ml_result,
                decision=fallback_decision,
                recommendations=rule_result.recommendations,
                analysis_completeness=response_completeness,
                engine_agreement=EngineAgreement.ml_unavailable,
                rule_raw_score=calculate_raw_risk_score(rule_result.signals),
                rule_adjusted_score=rule_result.risk_score,
                ml_prediction=None,
                ml_phishing_probability=None,
                ml_threshold=None,
                final_decision_confidence=fallback_decision['confidence'],
                rule_ml_agreement=EngineAgreement.ml_unavailable,
                fusion_reason='ML was unavailable; the decision uses deterministic rule evidence only.',
                positive_authentication_evidence=positive_authentication,
            )

        # Step 4: Final Decision Fusion
        if ml_result.prediction is None or ml_result.phishing_probability is None:
            raise RuntimeError('Available ML analysis did not produce a prediction')
        strong_malicious_evidence = any(
            signal.severity.value == 'high' and signal.score > 0 for signal in rule_result.signals
        )
        decision = fuse_analysis_results(
            rule_result=rule_result,
            ml_prediction=ml_result.prediction,
            ml_probability=ml_result.phishing_probability,
            authenticated_sender=authentication.trusted_sender,
            strong_malicious_evidence=strong_malicious_evidence,
        )
        if completeness.limited_evidence and str(decision.classification.value) == 'safe':
            decision = decision.model_copy(update={'confidence': min(decision.confidence, 0.65)})
        rule_suspicious = str(rule_result.classification.value) != 'safe'
        ml_suspicious = ml_result.prediction == 'phishing'
        agreement = EngineAgreement.agreement if rule_suspicious == ml_suspicious else EngineAgreement.disagreement
        response_completeness = self._qualify_safe_warning(
            completeness, str(decision.classification.value) == 'safe'
        )
        
        # Step 5: Generate unified response
        return UnifiedAnalysisResponse(
            parser=parsed_email,
            rule_analysis=rule_result,
            ml_analysis=ml_result,
            decision=decision,
            recommendations=rule_result.recommendations,
            analysis_completeness=response_completeness,
            engine_agreement=agreement,
            rule_raw_score=calculate_raw_risk_score(rule_result.signals),
            rule_adjusted_score=rule_result.risk_score,
            ml_prediction=ml_result.prediction,
            ml_phishing_probability=ml_result.phishing_probability,
            ml_threshold=ml_result.decision_threshold,
            final_decision_confidence=decision.confidence,
            rule_ml_agreement=agreement,
            fusion_reason=decision.fusion_reason,
            positive_authentication_evidence=positive_authentication,
        )

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
        )

    @staticmethod
    def _qualify_safe_warning(completeness: AnalysisCompleteness, is_safe: bool) -> AnalysisCompleteness:
        if not is_safe or not completeness.warning:
            return completeness
        detail = completeness.warning.removeprefix('Limited evidence:').strip()
        return completeness.model_copy(update={'warning': f'Safe based on limited evidence: {detail}'})

# Singleton instance for the API
pipeline = AnalysisPipeline()
