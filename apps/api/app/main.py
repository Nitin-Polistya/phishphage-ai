import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.logging import configure_logging
from app.core.settings import get_settings
from app.core.security import SecurityMiddleware
from app.routers.health import router as health_router

settings = get_settings()

configure_logging(settings.log_level)

logger = logging.getLogger(__name__)

app = FastAPI(
	title=settings.app_name,
	description='PhishPhage AI API for email parsing and phishing-risk analysis.',
	version=settings.app_version,
)

app.add_middleware(SecurityMiddleware, settings=settings)
app.add_middleware(
	CORSMiddleware,
	allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Accept', 'X-Request-ID'],
)

app.include_router(health_router)
app.include_router(api_router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    del request
    errors = [
        {'loc': error.get('loc', ['body']), 'msg': str(error.get('msg', 'Invalid input')), 'type': 'validation_error'}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={'detail': errors or [{'loc': ['body'], 'msg': 'Request validation failed.', 'type': 'validation_error'}]},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    del exc
    logger.error('Unhandled API exception', extra={'request_id': getattr(request.state, 'request_id', None)})
    return JSONResponse(
        status_code=500,
        content={'detail': {'code': 'internal_error', 'message': 'The request could not be completed.'}},
    )


@app.get('/')
def root() -> dict[str, str]:
	logger.info('Root endpoint requested')
	return {'message': 'PhishPhage AI API is running'}
