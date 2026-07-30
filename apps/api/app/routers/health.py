import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.runtime_metrics import runtime_metrics
from app.core.settings import get_settings
from app.services.inference_service import inference_service

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: str
    service: str


router = APIRouter()


@router.get('/health', response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(status='ok', service=get_settings().app_name)


@router.get('/ready')
def readiness() -> dict:
    settings = get_settings()
    health = inference_service.manager.health()
    metrics = runtime_metrics.snapshot()
    startup = runtime_metrics.startup_diagnostics()
    inference_ready = bool(health['inference_ready'] and startup.get('inference_ready', True))
    ready = metrics['startup_complete'] and health['registry_loaded'] and (
        not settings.ml_required or inference_ready
    )
    if not ready:
        from app.core.logging import log_event
        log_event(logger, logging.WARNING, 'readiness.failed',
                  reason_code=startup.get('reason_code') or health.get('reason_code') or 'not_ready',
                  startup_complete=metrics['startup_complete'],
                  registry_loaded=health['registry_loaded'],
                  model_available=health['model_available'],
                  inference_ready=inference_ready)
        raise HTTPException(status_code=503, detail={
            'code': 'service_not_ready',
            'message': 'Service readiness requirements are not satisfied.',
        })
    return {
        'status': 'ready',
        'service': settings.app_name,
        'startup_complete': metrics['startup_complete'],
        'registry_valid': health['registry_loaded'],
        'model_available': health['model_available'],
    }


@router.get('/metrics')
def metrics_endpoint() -> dict:
    health = inference_service.manager.health()
    startup = runtime_metrics.startup_diagnostics()
    model = {
        'loaded': bool(health['model_available'] and startup.get('model_available', True)),
        'model_id': startup.get('model_id') or health['loaded_model'],
        'model_version': startup.get('model_version') or health['model_version'],
        'registry_version': startup.get('registry_version') or health['registry_version'],
        'artifact_hash': startup.get('artifact_hash') or health['artifact_hash'],
        'inference_ready': bool(health['inference_ready'] and startup.get('inference_ready', True)),
    }
    return runtime_metrics.snapshot(model=model)
