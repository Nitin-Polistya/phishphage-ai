"""Isolated local dataset-review API; never imported by production analysis."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.core.settings import get_settings

from app.schemas.gemini_review import (
    DatasetReviewPreviewResponse,
    DatasetReviewStatus,
    DatasetReviewRecord,
    GeminiReviewSuggestRequest,
    HumanReviewRequest,
    SanitizedReviewInput,
    ReviewerDecisionImportRequest,
    ReviewerDecisionImportResponse,
    ReviewerQueueExportRequest,
    ReviewerQueueExportResponse,
    ReviewLabel,
)
from app.schemas.gold_dataset import (
    BatchImportRequest,
    BatchReviewResponse,
    DatasetReviewQueueResponse,
    GoldReviewState,
    SourceClaimedLabel,
)
from app.services.gemini_review_exports import reviewer_queue_csv, validate_decision_csv
from app.services.gold_dataset_manager import BatchImportError, GoldDatasetError
from app.services.gemini_review_service import GeminiReviewService, ReviewServiceError


router = APIRouter(prefix='/dataset-review')
review_service = GeminiReviewService()


def _service_error(error: ReviewServiceError) -> HTTPException:
    message = {
        'dataset_review_disabled': 'Dataset review is disabled.',
        'gemini_review_disabled': 'Gemini advisory review is disabled.',
        'unauthorized': 'Dataset review authorization failed.',
        'local_only_access_required': 'Dataset review is available only from the local machine.',
        'explicit_consent_required': 'Explicit consent is required for this specific sanitized payload.',
        'payload_hash_mismatch': 'The sanitized preview has changed. Generate a fresh preview and consent again.',
        'preview_expired': 'The sanitized preview is no longer valid. Generate a fresh preview and consent again.',
        'provider_not_configured': 'Gemini review is not configured.',
        'provider_model_not_configured': 'Gemini model configuration is missing.',
        'sanitization_failed': 'The evidence could not pass privacy validation.',
        'invalid_provider_schema': 'Gemini returned an invalid structured suggestion.',
        'provider_response_invalid': 'Gemini returned an unusable response.',
        'provider_blocked_response': 'Gemini did not return a review suggestion.',
        'empty_provider_response': 'Gemini returned an empty response.',
        'session_limit_reached': 'The per-session Gemini review limit has been reached.',
        'daily_limit_reached': 'The daily Gemini review limit has been reached.',
        'concurrency_limit_reached': 'The Gemini review concurrency limit has been reached.',
    }.get(error.code, 'Dataset review could not be completed safely.')
    return HTTPException(status_code=error.status_code, detail={'code': error.code, 'message': message})


def _feature_enabled() -> None:
    """Run before request-body validation so disabled routes fail closed."""
    if not get_settings().dataset_review_enabled:
        raise HTTPException(status_code=404, detail={'code': 'dataset_review_disabled', 'message': 'Dataset review is disabled.'})


def _gold_manager():
    # Keep the existing GoldDatasetManager singleton shared by both routers
    # without introducing an import cycle at module import time.
    from app.api.v1.gold_dataset import get_gold_dataset_manager
    return get_gold_dataset_manager()


@router.post('/batches/import', response_model=BatchReviewResponse, dependencies=[Depends(_feature_enabled)])
def import_dataset_review_batch(
    request: Request,
    payload: BatchImportRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> BatchReviewResponse:
    try:
        review_service.authorize(token=x_dataset_review_token, client_host=request.client.host if request.client else None, origin=request.headers.get('origin'))
        return _gold_manager().import_batch(payload)
    except BatchImportError as error:
        detail: dict[str, object] = {'code': 'invalid_batch', 'message': str(error)}
        if error.errors:
            detail['errors'] = error.errors
        raise HTTPException(status_code=422, detail=detail) from None
    except GoldDatasetError as error:
        raise HTTPException(status_code=409, detail={'code': 'batch_error', 'message': str(error)}) from None
    except ReviewServiceError as error:
        raise _service_error(error) from None


@router.get('/batches/{batch_id}', response_model=BatchReviewResponse, dependencies=[Depends(_feature_enabled)])
def get_dataset_review_batch(
    batch_id: str,
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
) -> BatchReviewResponse:
    try:
        review_service.authorize(token=x_dataset_review_token, client_host=request.client.host if request.client else None, origin=request.headers.get('origin'))
        return _gold_manager().get_batch(batch_id)
    except ReviewServiceError as error:
        raise _service_error(error) from None
    except GoldDatasetError as error:
        raise HTTPException(status_code=404, detail={'code': 'batch_not_found', 'message': 'Dataset review batch was not found.'}) from error


@router.get('/queue', response_model=DatasetReviewQueueResponse, dependencies=[Depends(_feature_enabled)])
def get_dataset_review_queue(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=100),
    source_label: SourceClaimedLabel | None = None,
    human_label: ReviewLabel | None = None,
    state: GoldReviewState | None = None,
    language: str | None = Query(default=None, max_length=32),
    source_dataset: str | None = Query(default=None, max_length=160),
    campaign: str | None = Query(default=None, max_length=160),
    duplicate_status: str | None = Query(default=None, max_length=40),
    second_review_required: bool | None = None,
    search: str | None = Query(default=None, max_length=160),
    x_dataset_review_token: str | None = Header(default=None),
) -> DatasetReviewQueueResponse:
    try:
        review_service.authorize(token=x_dataset_review_token, client_host=request.client.host if request.client else None, origin=request.headers.get('origin'))
        return _gold_manager().list_queue(page=page, page_size=page_size, source_label=source_label, human_label=human_label, state=state, language=language, source_dataset=source_dataset, campaign=campaign, duplicate_status=duplicate_status, second_review_required=second_review_required, search=search)
    except ReviewServiceError as error:
        raise _service_error(error) from None


@router.get('/status', response_model=DatasetReviewStatus)
def dataset_review_status() -> DatasetReviewStatus:
    """Return non-secret feature state so the UI can remain inactive by default."""
    return review_service.status()


@router.post('/preview', response_model=DatasetReviewPreviewResponse, dependencies=[Depends(_feature_enabled)])
def preview_dataset_review(
    request: Request,
    evidence: SanitizedReviewInput,
    x_dataset_review_token: str | None = Header(default=None),
) -> DatasetReviewPreviewResponse:
    try:
        review_service.authorize(
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
        payload, size = review_service.preview(evidence)
        return DatasetReviewPreviewResponse(
            enabled=True,
            payload=payload,
            payload_bytes=size,
            payload_hash=payload.sanitized_payload_hash,
            sent_fields=[
                'sample_id', 'subject', 'display_name', 'registrable domains',
                'authentication summary', 'sanitized body excerpt',
                'URL registrable domains and structural flags', 'attachment extension and MIME',
                'parser-derived evidence', 'candidate campaign category',
            ],
            notice='This preview contains sanitized evidence only. Gemini is external, advisory, and may process submitted data under applicable free-tier terms.',
        )
    except ReviewServiceError as error:
        raise _service_error(error) from None


@router.post('/suggest', response_model=dict, dependencies=[Depends(_feature_enabled)])
def request_gemini_suggestion(
    request: Request,
    payload: GeminiReviewSuggestRequest,
    x_dataset_review_token: str | None = Header(default=None),
    x_dataset_review_session: str | None = Header(default=None),
) -> dict:
    try:
        suggestion = review_service.submit(
            payload,
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
            session_id=x_dataset_review_session or 'local-tab-not-persisted',
        )
        return {'suggestion': suggestion.model_dump(mode='json'), 'advisory_only': True, 'ground_truth_changed': False}
    except ReviewServiceError as error:
        raise _service_error(error) from None


@router.post('/reviews', response_model=DatasetReviewRecord, dependencies=[Depends(_feature_enabled)])
def save_human_review(
    request: Request,
    payload: HumanReviewRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> DatasetReviewRecord:
    try:
        review_service.authorize(
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
        return review_service._store().save_human_review(payload)
    except ReviewServiceError as error:
        raise _service_error(error) from None
    except ValueError as error:
        raise HTTPException(status_code=409, detail={'code': 'review_conflict', 'message': str(error)}) from None


@router.get('/reviews/{sample_id}', response_model=DatasetReviewRecord)
def get_human_review(
    sample_id: str,
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
) -> DatasetReviewRecord:
    try:
        review_service.authorize(
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
        return review_service._store().get_record(sample_id)
    except ReviewServiceError as error:
        raise _service_error(error) from None
    except ValueError:
        raise HTTPException(status_code=404, detail={'code': 'review_not_found', 'message': 'Review record was not found.'}) from None


@router.post('/exports/queue', response_model=ReviewerQueueExportResponse, dependencies=[Depends(_feature_enabled)])
def export_reviewer_queue(
    request: Request,
    payload: ReviewerQueueExportRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> ReviewerQueueExportResponse:
    try:
        review_service.authorize(
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
        csv_text, package_hash = reviewer_queue_csv(payload.reviewer_id, payload.queue)
        return ReviewerQueueExportResponse(
            reviewer_id=payload.reviewer_id,
            package_version=payload.package_version,
            package_hash=package_hash,
            csv_text=csv_text,
        )
    except ReviewServiceError as error:
        raise _service_error(error) from None


@router.post('/imports/decisions', response_model=ReviewerDecisionImportResponse, dependencies=[Depends(_feature_enabled)])
def import_reviewer_decisions(
    request: Request,
    payload: ReviewerDecisionImportRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> ReviewerDecisionImportResponse:
    try:
        review_service.authorize(
            token=x_dataset_review_token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
        decisions, disagreements = validate_decision_csv(payload.csv_text, payload.reviewer_id, payload.package_hash)
        return ReviewerDecisionImportResponse(
            reviewer_id=payload.reviewer_id,
            package_hash=payload.package_hash,
            decisions=decisions,
            disagreement_queue=disagreements,
        )
    except ReviewServiceError as error:
        raise _service_error(error) from None
    except ValueError as error:
        raise HTTPException(status_code=422, detail={'code': 'invalid_review_package', 'message': str(error)}) from None
