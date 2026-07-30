import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import configure_logging, log_event
from app.core.settings import get_settings
from app.core.security import SecurityMiddleware
from app.core.runtime_metrics import runtime_metrics

settings_started = time.perf_counter()
settings = get_settings()
settings_initialization_ms = round((time.perf_counter() - settings_started) * 1000, 3)

configure_logging(settings.log_level, uvicorn_access_log=settings.uvicorn_access_log_enabled)

# Configure logging before importing modules with optional import-time
# initialization so their startup events are structured and privacy-safe.
from app.api.router import api_router
from app.core.firebase import is_firebase_configured
from app.services.inference_service import inference_service
from app.services.analysis_pipeline import pipeline
from app.routers.health import router as health_router

logger = logging.getLogger(__name__)

app = FastAPI(
	title=settings.app_name,
    description='PhishShield AI API for email parsing and phishing-risk analysis.',
	version=settings.app_version,
)

app.add_middleware(
	CORSMiddleware,
	allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Accept', 'X-Request-ID', 'X-Dataset-Review-Token', 'X-Dataset-Review-Session'],
)
app.add_middleware(SecurityMiddleware, settings=settings)

app.include_router(health_router)
app.include_router(api_router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    log_event(logger, logging.WARNING, 'request.validation_failed', endpoint=request.url.path,
              exception_class=type(exc).__name__, safe_message='request validation failed')
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
    fields = {
        'request_id': getattr(request.state, 'request_id', None),
        'endpoint': request.url.path,
        'exception_class': type(exc).__name__,
        'safe_message': 'internal server error',
    }
    # Keep the response and log payload safe even when an exception originates
    # in a parser or model dependency; tracebacks can contain input fragments.
    log_event(logger, logging.ERROR, 'request.failed', **fields)
    return JSONResponse(
        status_code=500,
        content={'detail': {'code': 'internal_error', 'message': 'The request could not be completed.'}},
    )


@app.get('/')
def root() -> dict[str, str]:
    return {'message': 'PhishShield AI API is running'}


def _round_ms(value: float | None) -> float:
    return round(max(0.0, value or 0.0), 3)


def _startup_diagnostics() -> dict:
    """Prepare all inference paths and publish one consistent startup state."""
    started = time.perf_counter()
    manager = inference_service.manager
    model_id = None
    registry_version = None
    artifact_hash = None
    model_configured = False
    pipeline_ready = False
    initialization_reason = None
    direct_timings: dict[str, float] = {}
    pipeline_timings: dict[str, float] = {}
    registry_timings: dict[str, float] = {}
    try:
        candidates = manager.discover_models()
        candidate = next((item for item in candidates if item.deployment_candidate), None)
        if candidate:
            model_configured = True
            model_id = candidate.model_id
            artifact_hash = candidate.sha256
        registry_version = manager._registry_version
        registry_timings = manager.last_timings
        if model_configured:
            direct_timings = inference_service.prepare()
            pipeline_timings = pipeline.prepare()
            pipeline_ready = pipeline.inference_ready
    except Exception as error:
        initialization_reason = getattr(error, 'code', None) or 'initialization_failed'
        if registry_version is None:
            registry_version = manager._registry_version or 'unavailable'

    try:
        health = manager.health()
    except Exception:
        health = {
            'loaded_model': None,
            'model_version': None,
            'registry_version': registry_version,
            'registry_status': 'unavailable',
            'registry_loaded': False,
            'artifact_found': False,
            'hash_verified': False,
            'model_available': False,
            'inference_ready': False,
            'reason_code': initialization_reason or 'health_unavailable',
            'artifact_hash': artifact_hash,
        }

    model_available = bool(health.get('model_available'))
    inference_ready = bool(health.get('inference_ready') and pipeline_ready)
    if not model_configured:
        inference_ready = False
    reason_code = initialization_reason or health.get('reason_code')
    fallback_allowed = not settings.ml_required
    startup_complete = fallback_allowed or inference_ready
    total_startup_ms = _round_ms((time.perf_counter() - started) * 1000)
    diagnostics = {
        'environment': settings.environment,
        'api_version': settings.app_version,
        'settings_initialization_ms': settings_initialization_ms,
        'registry_load_ms': _round_ms(registry_timings.get('registry_load_ms')),
        'artifact_hash_ms': _round_ms(direct_timings.get('artifact_hash_ms')),
        'model_load_ms': _round_ms(direct_timings.get('model_load_ms')),
        'adapter_construction_ms': _round_ms(pipeline_timings.get('adapter_construction_ms')),
        'model_warmup_ms': _round_ms(
            direct_timings.get('model_warmup_ms', 0.0) + pipeline_timings.get('model_warmup_ms', 0.0)
        ),
        'total_startup_ms': total_startup_ms,
        'model_id': health.get('loaded_model') or model_id,
        'model_version': health.get('model_version'),
        'registry_version': health.get('registry_version') or registry_version,
        'artifact_hash': health.get('artifact_hash') or artifact_hash,
        'registry_status': health.get('registry_status'),
        'registry_loaded': bool(health.get('registry_loaded')),
        'artifact_found': bool(health.get('artifact_found')),
        'artifact_hash_verified': bool(health.get('hash_verified')),
        'model_configured': model_configured,
        'model_available': model_available,
        'inference_ready': inference_ready,
        'pipeline_ready': pipeline_ready,
        'ml_required': settings.ml_required,
        'ml_enabled': inference_ready,
        'fallback_allowed': fallback_allowed,
        'fallback_active': fallback_allowed and not inference_ready,
        'firebase_enabled': is_firebase_configured(),
        'rate_limit_enabled': settings.rate_limit_enabled,
        'cors_origin_count': len(settings.cors_origins),
        'max_request_bytes': settings.max_request_bytes,
        'uvicorn_access_log': settings.uvicorn_access_log_enabled,
        'reason_code': reason_code,
        'startup_complete': startup_complete,
    }

    required_startup_failed = settings.ml_required and not inference_ready
    if required_startup_failed:
        # Do not leave a direct predictor or adapter cached when the complete
        # required startup contract was not satisfied.
        manager.clear_loaded_state()
        pipeline.clear_loaded_state()
        diagnostics.update({
            'model_available': False,
            'inference_ready': False,
            'pipeline_ready': False,
            'ml_enabled': False,
            'startup_complete': False,
        })

    runtime_metrics.set_startup_diagnostics(diagnostics)
    log_event(logger, logging.INFO, 'startup.diagnostics', **diagnostics)
    if diagnostics['registry_loaded']:
        log_event(logger, logging.INFO, 'model.registry_loaded',
                  model_id=diagnostics['model_id'], registry_version=diagnostics['registry_version'])
    if diagnostics['artifact_hash_verified']:
        log_event(logger, logging.INFO, 'model.artifact_verified',
                  model_id=diagnostics['model_id'], artifact_hash=diagnostics['artifact_hash'],
                  artifact_hash_verified=True)
    if diagnostics['model_available']:
        log_event(logger, logging.INFO, 'model.loaded', model_id=diagnostics['model_id'],
                  model_version=diagnostics['model_version'])
    if diagnostics['inference_ready']:
        log_event(logger, logging.INFO, 'model.warmup_complete',
                  model_id=diagnostics['model_id'], model_warmup_ms=diagnostics['model_warmup_ms'])
    if required_startup_failed:
        log_event(logger, logging.ERROR, 'startup.failed',
                  reason_code=reason_code or 'required_model_unavailable',
                  ml_required=True, model_available=False, inference_ready=False)
        raise RuntimeError('Required inference initialization failed')
    return diagnostics


def _shutdown_complete() -> None:
    diagnostics = runtime_metrics.startup_diagnostics()
    log_event(logger, logging.INFO, 'shutdown.complete',
              startup_complete=bool(diagnostics.get('startup_complete', False)),
              uptime_seconds=runtime_metrics.snapshot().get('uptime_seconds', 0.0))


app.router.add_event_handler('shutdown', _shutdown_complete)


_startup_diagnostics()
