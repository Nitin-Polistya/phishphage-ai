"""Phase III gold-dataset routes inside the local Dataset Review boundary."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.api.v1.dataset_review import _feature_enabled, review_service
from app.schemas.gold_dataset import (
    GoldDatasetDashboard,
    GoldDatasetExportResponse,
    GoldDatasetReview,
    GoldDatasetReviewInput,
    GoldReviewRevisionRequest,
    GoldReviewState,
    ReviewerDecisionInput,
    ReviewTransitionRequest,
    BulkLabelRequest,
    BulkOperationResponse,
    BulkReviewSettingsRequest,
    BulkTransitionRequest,
)
from app.services.gold_dataset_manager import (
    DuplicateReviewError,
    ExportStorageError,
    ExportVerificationError,
    GoldDatasetError,
    GoldDatasetManager,
    NoApprovedRecordsError,
)
from app.services.gemini_review_service import ReviewServiceError


router = APIRouter(prefix='/dataset-review/gold-dataset')
_manager: GoldDatasetManager | None = None


def get_gold_dataset_manager() -> GoldDatasetManager:
    global _manager
    if _manager is None:
        _manager = GoldDatasetManager()
    return _manager


def _authorize(request: Request, token: str | None) -> None:
    try:
        review_service.authorize(
            token=token,
            client_host=request.client.host if request.client else None,
            origin=request.headers.get('origin'),
        )
    except ReviewServiceError as error:
        message = 'Dataset review authorization failed.' if error.code == 'unauthorized' else 'Dataset review is unavailable.'
        raise HTTPException(status_code=error.status_code, detail={'code': error.code, 'message': message}) from None


def _gold_error(error: GoldDatasetError) -> HTTPException:
    code = 'duplicate_review' if isinstance(error, DuplicateReviewError) else 'gold_dataset_error'
    status = 409 if code == 'duplicate_review' else 422
    return HTTPException(status_code=status, detail={'code': code, 'message': str(error)})


def _bulk_response(request: Request, token: str | None, handler) -> BulkOperationResponse:
    _authorize(request, token)
    try:
        return handler()
    except GoldDatasetError as error:
        raise _gold_error(error) from None


@router.post('/bulk-label', response_model=BulkOperationResponse, dependencies=[Depends(_feature_enabled)])
def bulk_label_gold_reviews(request: Request, payload: BulkLabelRequest, x_dataset_review_token: str | None = Header(default=None)) -> BulkOperationResponse:
    return _bulk_response(request, x_dataset_review_token, lambda: get_gold_dataset_manager().bulk_label(payload))


@router.post('/bulk-transition', response_model=BulkOperationResponse, dependencies=[Depends(_feature_enabled)])
def bulk_transition_gold_reviews(request: Request, payload: BulkTransitionRequest, x_dataset_review_token: str | None = Header(default=None)) -> BulkOperationResponse:
    return _bulk_response(request, x_dataset_review_token, lambda: get_gold_dataset_manager().bulk_transition(payload))


@router.post('/bulk-review-settings', response_model=BulkOperationResponse, dependencies=[Depends(_feature_enabled)])
def bulk_review_settings(request: Request, payload: BulkReviewSettingsRequest, x_dataset_review_token: str | None = Header(default=None)) -> BulkOperationResponse:
    return _bulk_response(request, x_dataset_review_token, lambda: get_gold_dataset_manager().bulk_review_settings(payload))


@router.get('/dashboard', response_model=GoldDatasetDashboard)
def gold_dataset_dashboard(
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
    _: None = Depends(_feature_enabled),
) -> GoldDatasetDashboard:
    _authorize(request, x_dataset_review_token)
    return get_gold_dataset_manager().dashboard()


@router.get('/agreement')
def gold_dataset_agreement(
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
    _: None = Depends(_feature_enabled),
):
    _authorize(request, x_dataset_review_token)
    return get_gold_dataset_manager().latest_agreement()


@router.get('/reviews', response_model=list[GoldDatasetReview])
def list_gold_reviews(
    request: Request,
    state: GoldReviewState | None = None,
    x_dataset_review_token: str | None = Header(default=None),
    _: None = Depends(_feature_enabled),
) -> list[GoldDatasetReview]:
    _authorize(request, x_dataset_review_token)
    return get_gold_dataset_manager().list_reviews(state)


@router.post('/reviews', response_model=GoldDatasetReview, dependencies=[Depends(_feature_enabled)])
def create_gold_review(
    request: Request,
    payload: GoldDatasetReviewInput,
    x_dataset_review_token: str | None = Header(default=None),
) -> GoldDatasetReview:
    _authorize(request, x_dataset_review_token)
    try:
        return get_gold_dataset_manager().create_review(payload)
    except GoldDatasetError as error:
        raise _gold_error(error) from None


@router.get('/reviews/{review_id}', response_model=GoldDatasetReview)
def get_gold_review(
    review_id: UUID,
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
    _: None = Depends(_feature_enabled),
) -> GoldDatasetReview:
    _authorize(request, x_dataset_review_token)
    try:
        return get_gold_dataset_manager().get_review(review_id)
    except GoldDatasetError as error:
        raise HTTPException(status_code=404, detail={'code': 'gold_review_not_found', 'message': 'Gold review was not found.'}) from error


@router.post('/reviews/{review_id}/decisions', response_model=GoldDatasetReview, dependencies=[Depends(_feature_enabled)])
def add_gold_reviewer_decision(
    review_id: UUID,
    request: Request,
    payload: ReviewerDecisionInput,
    x_dataset_review_token: str | None = Header(default=None),
) -> GoldDatasetReview:
    _authorize(request, x_dataset_review_token)
    try:
        return get_gold_dataset_manager().add_reviewer_decision(review_id, payload)
    except GoldDatasetError as error:
        raise _gold_error(error) from None


@router.post('/reviews/{review_id}/transition', response_model=GoldDatasetReview, dependencies=[Depends(_feature_enabled)])
def transition_gold_review(
    review_id: UUID,
    request: Request,
    payload: ReviewTransitionRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> GoldDatasetReview:
    _authorize(request, x_dataset_review_token)
    try:
        return get_gold_dataset_manager().transition_state(review_id, payload.reviewer_name, payload.new_state, payload.reason)
    except GoldDatasetError as error:
        raise _gold_error(error) from None


@router.post('/reviews/{review_id}/revise', response_model=GoldDatasetReview, dependencies=[Depends(_feature_enabled)])
def revise_gold_review(
    review_id: UUID,
    request: Request,
    payload: GoldReviewRevisionRequest,
    x_dataset_review_token: str | None = Header(default=None),
) -> GoldDatasetReview:
    _authorize(request, x_dataset_review_token)
    try:
        return get_gold_dataset_manager().revise_review(review_id, payload.reviewer_name, phishing_label=payload.phishing_label, reviewer_confidence=payload.reviewer_confidence, review_notes=payload.review_notes, reason=payload.reason)
    except GoldDatasetError as error:
        raise _gold_error(error) from None


@router.get('/reviews/{review_id}/audit')
def gold_review_audit(
    review_id: UUID,
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
    _: None = Depends(_feature_enabled),
):
    _authorize(request, x_dataset_review_token)
    try:
        get_gold_dataset_manager().get_review(review_id)
        return get_gold_dataset_manager().get_audit_trail(review_id)
    except GoldDatasetError as error:
        raise HTTPException(status_code=404, detail={'code': 'gold_review_not_found', 'message': 'Gold review was not found.'}) from error


@router.post('/export', response_model=GoldDatasetExportResponse, dependencies=[Depends(_feature_enabled)])
def export_gold_dataset(
    request: Request,
    x_dataset_review_token: str | None = Header(default=None),
) -> GoldDatasetExportResponse:
    _authorize(request, x_dataset_review_token)
    manager = get_gold_dataset_manager()
    try:
        exported = manager.export_gold_dataset()
        reports = manager.generate_reports(exported['directory'])
        paths = [*exported['files'], *reports.values()]
        file_details = manager.verify_export_files(paths)
    except NoApprovedRecordsError as error:
        raise HTTPException(status_code=409, detail={'code': 'no_approved_records', 'message': str(error)}) from None
    except ExportVerificationError as error:
        raise HTTPException(status_code=500, detail={'code': 'export_file_verification_failed', 'message': str(error)}) from None
    except ExportStorageError as error:
        raise HTTPException(status_code=500, detail={'code': 'export_storage_failure', 'message': str(error)}) from None
    except GoldDatasetError as error:
        raise _gold_error(error) from None
    except OSError:
        raise HTTPException(status_code=500, detail={'code': 'export_storage_failure', 'message': 'The local export storage failed safely.'}) from None
    return GoldDatasetExportResponse(
        exported_count=int(exported['exported_samples']),
        exported_at=str(exported['exported_at']),
        output_location=str(exported['directory_relative']),
        files=file_details,
        all_files_written=bool(file_details) and all(item['status'] == 'written' for item in file_details),
        privacy_contract='Approved human-reviewed metadata only; raw email, headers, URLs, addresses, Message-ID, attachment contents, and PII are excluded.',
    )
