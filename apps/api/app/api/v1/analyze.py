from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException

from app.core.logging import log_event
from app.schemas.email import ParsedEmail
from app.schemas.inference import AnalyzeRequest, PredictionResponse
from app.services.email_parser import parse_email
from app.services.inference_service import inference_service
from app.services.model_manager import ModelManagerError

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post('/analyze', response_model=PredictionResponse)
def analyze_email(payload: AnalyzeRequest) -> PredictionResponse:
    started = time.perf_counter()
    parser_started = time.perf_counter()
    try:
        parsed: ParsedEmail = parse_email(payload.raw_email)
        parser_ms = (time.perf_counter() - parser_started) * 1000
        response = inference_service.predict_email(parsed)
        log_event(logger, logging.DEBUG, 'analysis.timing',
                  parser_ms=round(parser_ms, 3), rules_ms=0.0,
                  inference_ms=round(response.processing_time_ms, 3),
                  total_ms=round((time.perf_counter() - started) * 1000, 3))
        return response
    except ValueError as error:
        raise HTTPException(status_code=400, detail={"code": "invalid_email", "message": str(error)}) from None
    except ModelManagerError as error:
        raise HTTPException(status_code=503, detail={"code": error.code, "message": str(error)}) from None
    except Exception:
        raise HTTPException(status_code=500, detail={"code": "inference_failure", "message": "Inference failed safely."}) from None
