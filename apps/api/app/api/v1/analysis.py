"""Analysis endpoints (dev preview)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.analysis import UnifiedAnalysisResponse
from app.schemas.email import EmailParserRequest
from app.services.analysis_pipeline import MLUnavailableError, pipeline

router = APIRouter()


@router.post('/analysis/preview', response_model=UnifiedAnalysisResponse)
def preview_analysis(payload: EmailParserRequest):
    try:
        result = pipeline.run(payload.raw_email)
    except ValueError as e:
        # parser raised a validation error for email content
        raise HTTPException(status_code=400, detail=str(e))
    except MLUnavailableError:
        raise HTTPException(
            status_code=503,
            detail='Machine-learning analysis is temporarily unavailable.',
        )
    except Exception:
        raise HTTPException(status_code=500, detail='Internal server error')
    return result
