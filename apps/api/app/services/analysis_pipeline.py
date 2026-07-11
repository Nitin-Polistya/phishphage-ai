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
from app.services.email_parser import parse_email
from app.services.phishing_analyzer import analyze_parsed_email
from app.services.decision_engine import fuse_analysis_results
from app.schemas.analysis import UnifiedAnalysisResponse, MLAnalysisResult

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
        parsed_email = parse_email(raw_email)
        
        # Step 2: Run rule-based analyzer
        rule_result = analyze_parsed_email(parsed_email)
        
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
            )

            return UnifiedAnalysisResponse(
                parser=parsed_email,
                rule_analysis=rule_result,
                ml_analysis=ml_result,
                decision={
                    'classification': rule_result.classification,
                    'risk_score': rule_result.risk_score,
                    'confidence': rule_result.confidence,
                },
                recommendations=rule_result.recommendations,
            )

        # Step 4: Final Decision Fusion
        if ml_result.prediction is None or ml_result.phishing_probability is None:
            raise RuntimeError('Available ML analysis did not produce a prediction')
        decision = fuse_analysis_results(
            rule_result=rule_result,
            ml_prediction=ml_result.prediction,
            ml_probability=ml_result.phishing_probability,
        )
        
        # Step 5: Generate unified response
        return UnifiedAnalysisResponse(
            parser=parsed_email,
            rule_analysis=rule_result,
            ml_analysis=ml_result,
            decision=decision,
            recommendations=rule_result.recommendations
        )

# Singleton instance for the API
pipeline = AnalysisPipeline()
