"""Email parser API endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.core.logging import log_event
from app.schemas.email import EmailParserRequest, ParsedEmail
from app.services.email_parser import parse_email

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post('/parser/preview', response_model=ParsedEmail)
def preview_email_parser(request: EmailParserRequest) -> ParsedEmail:
    """Preview email parsing output (development endpoint).
    
    Accepts raw email content and returns the normalized parsed structure.
    Useful for testing the parser before integration.
    
    Args:
        request: EmailParserRequest with raw_email field
        
    Returns:
        ParsedEmail with extracted components
        
    Raises:
        HTTPException 400: If input is invalid
        HTTPException 500: If parsing fails
    """
    try:
        parsed = parse_email(request.raw_email)
        log_event(logger, logging.INFO, 'parser.complete', success=True)
        return parsed
    except ValueError as e:
        log_event(logger, logging.WARNING, 'parser.failed', success=False,
                  reason_code='invalid_email_format', exception_class=type(e).__name__)
        raise HTTPException(status_code=400, detail=str(e)) from None
    except Exception as error:
        log_event(logger, logging.ERROR, 'parser.failed', success=False,
                  reason_code='parser_error', exception_class=type(error).__name__)
        raise HTTPException(status_code=500, detail={'code': 'analysis_failed', 'message': 'Failed to parse email'}) from None
