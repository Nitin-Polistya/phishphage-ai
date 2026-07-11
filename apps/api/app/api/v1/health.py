from fastapi import APIRouter
from pydantic import BaseModel

from app.core.firebase import is_firebase_configured


class HealthResponse(BaseModel):
    status: str
    service: str
    firebase: str


router = APIRouter()


@router.get('/health', response_model=HealthResponse)
def health_check() -> HealthResponse:
    firebase_status = 'configured' if is_firebase_configured() else 'not_configured'
    return HealthResponse(status='ok', service='phishshield-api', firebase=firebase_status)