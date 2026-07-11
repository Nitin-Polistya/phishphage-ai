"""Email parser API endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

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
        logger.info(f'Email parsed successfully: {len(parsed.body_text)} chars')
        return parsed
    except ValueError as e:
        logger.warning(f'Email validation failed: {e}')
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f'Email parsing failed: {e}')
        raise HTTPException(status_code=500, detail='Failed to parse email')
