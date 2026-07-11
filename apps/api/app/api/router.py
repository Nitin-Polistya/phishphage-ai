from fastapi import APIRouter

from app.api.v1.email_parser import router as v1_email_parser_router
from app.api.v1.health import router as v1_health_router
from app.api.v1.analysis import router as v1_analysis_router

api_router = APIRouter()

api_router.include_router(v1_health_router, prefix='/api/v1', tags=['v1'])
api_router.include_router(v1_email_parser_router, prefix='/api/v1', tags=['v1'])
api_router.include_router(v1_analysis_router, prefix='/api/v1', tags=['v1'])