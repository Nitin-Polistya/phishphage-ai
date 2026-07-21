from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.firebase import is_firebase_configured
from app.services.model_manager import ModelManager
from app.services.inference_service import inference_service
from app.core.settings import get_settings


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
    registry_loaded: bool = False
    artifact_found: bool = False
    hash_verified: bool = False
    model_available: bool = False
    inference_ready: bool = False
    reason_code: str | None = None


router = APIRouter()


@router.get('/health', response_model=HealthResponse)
def health_check() -> HealthResponse:
    firebase_status = 'configured' if is_firebase_configured() else 'not_configured'
    health = inference_service.manager.health()
    if get_settings().ml_required and not health['inference_ready']:
        raise HTTPException(
            status_code=503,
            detail={
                'code': 'model_unavailable',
                'message': 'Approved inference model is unavailable.',
            },
        )
    return HealthResponse(
        status='ok' if health['inference_ready'] else 'degraded',
        service='phishshield-api',
        firebase=firebase_status,
        **health,
    )
