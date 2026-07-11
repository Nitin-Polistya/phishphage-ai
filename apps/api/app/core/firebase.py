"""Firebase Admin SDK initialization and helpers."""

from __future__ import annotations

import json
import logging
from typing import Any

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

from app.core.settings import get_settings

logger = logging.getLogger(__name__)

_firebase_app: firebase_admin.App | None = None
_firestore_client: firestore.client | None = None
_firebase_configured: bool = False


def _initialize_firebase() -> None:
    """Initialize Firebase Admin SDK if credentials are available.
    
    This function is called once at module import time.
    If Firebase credentials are not configured, initialization is skipped
    and a warning is logged. The API will continue to run normally.
    """
    global _firebase_app, _firebase_configured

    settings = get_settings()

    if (
        not settings.firebase_project_id
        or not settings.firebase_client_email
        or not settings.firebase_private_key
    ):
        logger.warning(
            'Firebase credentials not configured. '
            'Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY to enable Firebase.'
        )
        return

    try:
        private_key = settings.firebase_private_key.replace('\\n', '\n')

        cred_dict: dict[str, Any] = {
            'type': 'service_account',
            'project_id': settings.firebase_project_id,
            'private_key_id': None,
            'private_key': private_key,
            'client_email': settings.firebase_client_email,
            'client_id': None,
            'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token',
        }

        cred = credentials.Certificate(cred_dict)
        _firebase_app = firebase_admin.initialize_app(cred, name='phishshield')
        _firebase_configured = True
        logger.info(f'Firebase initialized for project: {settings.firebase_project_id}')
    except Exception as e:
        logger.error(f'Failed to initialize Firebase: {e}')
        _firebase_configured = False


def is_firebase_configured() -> bool:
    """Return whether Firebase is available and initialized."""
    return _firebase_configured


def get_firestore_client() -> firestore.client | None:
    """Get the Firestore client instance if Firebase is configured, otherwise None.
    
    Note: This is a helper function that returns the client.
    Actual database operations should be implemented in service modules.
    """
    global _firestore_client

    if not _firebase_configured:
        return None

    if _firestore_client is None:
        _firestore_client = firestore.client(_firebase_app)

    return _firestore_client


_initialize_firebase()
