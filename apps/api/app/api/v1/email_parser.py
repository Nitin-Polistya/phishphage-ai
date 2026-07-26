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
        logger.info('Email parsed successfully', extra={'body_length': len(parsed.body_text)})
        return parsed
    except ValueError as e:
        logger.warning('Email validation failed', extra={'reason_code': 'invalid_email_format'})
        raise HTTPException(status_code=400, detail=str(e)) from None
    except Exception:
        logger.error('Email parsing failed safely')
        raise HTTPException(status_code=500, detail={'code': 'analysis_failed', 'message': 'Failed to parse email'}) from None
