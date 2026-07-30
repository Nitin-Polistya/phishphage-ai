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
)
from app.services.gold_dataset_manager import DuplicateReviewError, GoldDatasetError, GoldDatasetManager
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
    exported = manager.export_gold_dataset()
    reports = manager.generate_reports()
    return GoldDatasetExportResponse(
        export_directory='private local evaluation storage',
        exported_samples=int(exported['exported_samples']),
        files=[path.name for path in [*exported['files'], *reports.values()]],
        privacy_contract='Approved human-reviewed metadata only; raw email, headers, URLs, addresses, Message-ID, attachment contents, and PII are excluded.',
    )
