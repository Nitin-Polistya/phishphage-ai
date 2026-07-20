from fastapi import APIRouter
from pydantic import BaseModel

from app.core.firebase import is_firebase_configured
from app.services.model_manager import ModelManager
from app.services.inference_service import inference_service


class HealthResponse(BaseModel):
    status: str
    service: str
    firebase: str
    loaded_model: str | None = None
    model_version: str | None = None
    calibration: str | None = None
    deployment_candidate: bool = False
    activated: bool = False
    pipeline_sha: str | None = None
    registry_status: str | None = None


router = APIRouter()


@router.get('/health', response_model=HealthResponse)
def health_check() -> HealthResponse:
    firebase_status = 'configured' if is_firebase_configured() else 'not_configured'
    return HealthResponse(status='ok', service='phishshield-api', firebase=firebase_status, **inference_service.manager.health())
