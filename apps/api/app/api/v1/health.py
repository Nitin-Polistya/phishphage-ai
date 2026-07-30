from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.firebase import is_firebase_configured
from app.services.model_manager import ModelManager
from app.services.inference_service import inference_service
from app.core.settings import get_settings
from app.core.runtime_metrics import runtime_metrics


class HealthResponse(BaseModel):
    status: str
    service: str
    firebase: str
    firebase_enabled: bool = False
    loaded_model: str | None = None
    model_version: str | None = None
    calibration: str | None = None
    deployment_candidate: bool = False
    activated: bool = False
    pipeline_sha: str | None = None
    artifact_hash: str | None = None
    registry_version: str | None = None
    registry_status: str | None = None
    registry_loaded: bool = False
    artifact_found: bool = False
    hash_verified: bool = False
    model_available: bool = False
    inference_ready: bool = False
    reason_code: str | None = None
    application_version: str
    environment: str
    uptime_seconds: float
    startup_time: str
    startup_complete: bool
    request_counts: dict[str, int]
    analysis_counts: dict[str, int]
    rate_limiter_enabled: bool


router = APIRouter()


@router.get('/health', response_model=HealthResponse)
def health_check() -> HealthResponse:
    firebase_status = 'configured' if is_firebase_configured() else 'not_configured'
    health = inference_service.manager.health()
    startup = runtime_metrics.startup_diagnostics()
    if startup:
        health['inference_ready'] = bool(
            health['inference_ready'] and startup.get('inference_ready', True)
        )
        if not health['inference_ready']:
            health['reason_code'] = startup.get('reason_code') or health.get('reason_code')
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
        service=get_settings().app_name,
        firebase=firebase_status,
        firebase_enabled=firebase_status == 'configured',
        application_version=get_settings().app_version,
        environment=get_settings().environment,
        **_health_metrics(),
        **health,
    )


def _health_metrics() -> dict:
    metrics = runtime_metrics.snapshot()
    return {
        'uptime_seconds': metrics['uptime_seconds'],
        'startup_time': metrics['startup_time'],
        'startup_complete': metrics['startup_complete'],
        'request_counts': {
            'total': metrics['total_requests'],
            'successful': metrics['successful_requests'],
            'failed': metrics['failed_requests'],
        },
        'analysis_counts': {
            'total': metrics['total_analysis_requests'],
            'inference_calls': metrics['model_inference_calls'],
        },
        'rate_limiter_enabled': get_settings().rate_limit_enabled,
    }
