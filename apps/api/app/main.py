import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.logging import configure_logging
from app.core.settings import get_settings
from app.routers.health import router as health_router

settings = get_settings()

configure_logging(settings.log_level)

logger = logging.getLogger(__name__)

app = FastAPI(
	title=settings.app_name,
	description='PhishPhage AI API for email parsing and phishing-risk analysis.',
	version=settings.app_version,
)

app.add_middleware(
	CORSMiddleware,
	allow_origins=settings.cors_origins,
	allow_credentials=True,
	allow_methods=['*'],
	allow_headers=['*'],
)

app.include_router(health_router)
app.include_router(api_router)


@app.get('/')
def root() -> dict[str, str]:
	logger.info('Root endpoint requested')
	return {'message': 'PhishPhage AI API is running'}
