from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.email import ParsedEmail
from app.schemas.inference import AnalyzeRequest, PredictionResponse
from app.services.email_parser import parse_email
from app.services.inference_service import inference_service
from app.services.model_manager import ModelManagerError

router = APIRouter()


@router.post('/analyze', response_model=PredictionResponse)
def analyze_email(payload: AnalyzeRequest) -> PredictionResponse:
    try:
        parsed: ParsedEmail = parse_email(payload.raw_email)
        return inference_service.predict_email(parsed)
    except ValueError as error:
        raise HTTPException(status_code=400, detail={"code": "invalid_email", "message": str(error)}) from None
    except ModelManagerError as error:
        raise HTTPException(status_code=503, detail={"code": error.code, "message": str(error)}) from None
    except Exception:
        raise HTTPException(status_code=500, detail={"code": "inference_failure", "message": "Inference failed safely."}) from None
