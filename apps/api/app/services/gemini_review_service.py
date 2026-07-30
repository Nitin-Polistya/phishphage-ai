"""Server-side Gemini advisory service with strict privacy and rate controls."""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import threading
import time
import uuid
from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Any, Callable

from app.core.logging import log_event
from app.core.settings import Settings, get_settings
from app.schemas.gemini_review import (
    DatasetReviewStatus,
    GeminiReviewSuggestion,
    GeminiReviewSuggestRequest,
    ProviderUsage,
    SanitizedReviewInput,
    SanitizedReviewPayload,
)
from app.services.gemini_review_prompt import PROMPT_VERSION, build_review_prompt
from app.services.gemini_review_sanitizer import (
    SanitizationError,
    payload_bytes,
    sanitize_review_input,
    validate_payload_before_submission,
)
from app.services.gemini_review_storage import ReviewStore


logger = logging.getLogger(__name__)


class ReviewServiceError(RuntimeError):
    def __init__(self, code: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class ReviewLimitError(ReviewServiceError):
    pass


class _ReviewCounters:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session: dict[str, int] = defaultdict(int)
        self._day: dict[date, int] = defaultdict(int)
        self._today = date.today()

    def reserve(self, session_id: str, *, session_limit: int, daily_limit: int) -> None:
        now = date.today()
        with self._lock:
            if now != self._today:
                self._day.clear()
                self._today = now
            if self._session[session_id] >= session_limit:
                raise ReviewLimitError('session_limit_reached', 429)
            if self._day[now] >= daily_limit:
                raise ReviewLimitError('daily_limit_reached', 429)
            self._session[session_id] += 1
            self._day[now] += 1

    def snapshot(self, session_id: str | None = None) -> dict[str, int]:
        with self._lock:
            return {'session_used': self._session.get(session_id or '', 0), 'daily_used': self._day.get(date.today(), 0)}


def is_loopback_client(client_host: str | None) -> bool:
    if not client_host:
        return False
    if client_host.lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return False


class GeminiReviewService:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        store: ReviewStore | None = None,
        client_factory: Callable[[Settings], Any] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.client_factory = client_factory
        self._counters = _ReviewCounters()
        self._semaphore: threading.BoundedSemaphore | None = None
        self._semaphore_limit: int | None = None
        self._lock = threading.Lock()

    def _settings(self) -> Settings:
        return self.settings or get_settings()

    def _store(self) -> ReviewStore:
        if self.store is None:
            self.store = ReviewStore()
        return self.store

    def _configured(self) -> bool:
        settings = self._settings()
        return bool(settings.gemini_api_key and settings.gemini_model and settings.dataset_review_admin_token)

    def status(self) -> DatasetReviewStatus:
        settings = self._settings()
        configured = self._configured()
        return DatasetReviewStatus(
            enabled=settings.dataset_review_enabled,
            local_only=settings.dataset_review_local_only,
            gemini_enabled=settings.gemini_review_enabled,
            configured=configured,
            provider_ready=bool(settings.gemini_review_enabled and settings.gemini_api_key and settings.gemini_model),
            model_name=settings.gemini_model,
            prompt_version=settings.gemini_prompt_version or PROMPT_VERSION,
            session_limit=settings.gemini_session_review_limit,
            daily_limit=settings.gemini_daily_review_limit,
            batch_enabled=False,
            storage='local SQLite; sanitized metadata only',
            notice='Gemini suggestions are advisory. A human reviewer must approve every final label.',
        )

    def authorize(self, *, token: str | None, client_host: str | None, origin: str | None) -> None:
        settings = self._settings()
        if not settings.dataset_review_enabled:
            raise ReviewServiceError('dataset_review_disabled', 404)
        if settings.dataset_review_local_only and not is_loopback_client(client_host):
            raise ReviewServiceError('local_only_access_required', 403)
        if origin and origin.rstrip('/') not in {item.rstrip('/') for item in settings.cors_origins}:
            raise ReviewServiceError('unauthorized', 401)
        configured_token = settings.dataset_review_admin_token
        if not configured_token or not token or not secrets.compare_digest(token, configured_token):
            raise ReviewServiceError('unauthorized', 401)

    def preview(self, evidence: SanitizedReviewInput) -> tuple[SanitizedReviewPayload, int]:
        settings = self._settings()
        if not settings.dataset_review_enabled:
            raise ReviewServiceError('dataset_review_disabled', 404)
        if not settings.gemini_model:
            raise ReviewServiceError('provider_model_not_configured', 503)
        try:
            payload = sanitize_review_input(
                evidence,
                model_name=settings.gemini_model,
                prompt_version=settings.gemini_prompt_version or PROMPT_VERSION,
                settings=settings,
            )
        except SanitizationError as error:
            log_event(logger, logging.WARNING, 'dataset_review.preview_rejected', reason_code='sanitization_failed')
            raise ReviewServiceError('sanitization_failed', 422) from error
        self._store().save_preview(payload)
        return payload, payload_bytes(payload)

    def submit(
        self,
        request: GeminiReviewSuggestRequest,
        *,
        token: str | None,
        client_host: str | None,
        origin: str | None,
        session_id: str,
    ) -> GeminiReviewSuggestion:
        self.authorize(token=token, client_host=client_host, origin=origin)
        settings = self._settings()
        if not settings.gemini_review_enabled:
            raise ReviewServiceError('gemini_review_disabled', 404)
        if not request.consent:
            raise ReviewServiceError('explicit_consent_required', 400)
        try:
            validate_payload_before_submission(request.payload, settings)
        except SanitizationError as error:
            code = 'payload_hash_mismatch' if 'hash' in str(error).lower() else 'sanitization_failed'
            raise ReviewServiceError(code, 422) from error
        if request.payload.model_name != settings.gemini_model or request.payload.prompt_version != (settings.gemini_prompt_version or PROMPT_VERSION):
            raise ReviewServiceError('preview_expired', 409)
        if not settings.gemini_api_key or not settings.gemini_model:
            raise ReviewServiceError('provider_not_configured', 503)
        if not session_id or len(session_id) > 100:
            raise ReviewServiceError('invalid_review_session', 400)
        self._counters.reserve(
            session_id,
            session_limit=min(settings.gemini_session_review_limit, 5),
            daily_limit=min(settings.gemini_daily_review_limit, 10),
        )
        semaphore = self._get_semaphore(settings.gemini_max_concurrent_requests)
        if not semaphore.acquire(timeout=max(1, settings.gemini_request_timeout_seconds)):
            raise ReviewLimitError('concurrency_limit_reached', 429)
        try:
            suggestion = self._call_provider(request.payload, settings)
            self._store().save_suggestion(
                request.payload,
                suggestion,
                mode=request.review_mode,
                reviewer_alias=request.reviewer_alias,
                preliminary_label=request.preliminary_label,
                preliminary_confidence=request.preliminary_confidence,
                preliminary_notes=request.preliminary_notes,
            )
            return suggestion
        except ReviewServiceError:
            raise
        except Exception as error:
            # Do not return or log provider exception bodies: they can contain
            # submitted content or SDK diagnostics.
            log_event(logger, logging.WARNING, 'dataset_review.provider_failed', reason_code='provider_error', exception_class=type(error).__name__)
            raise ReviewServiceError('provider_error', 502) from None
        finally:
            semaphore.release()

    def _get_semaphore(self, limit: int) -> threading.BoundedSemaphore:
        with self._lock:
            safe_limit = min(max(1, limit), 4)
            if self._semaphore is None or self._semaphore_limit != safe_limit:
                self._semaphore = threading.BoundedSemaphore(safe_limit)
                self._semaphore_limit = safe_limit
            return self._semaphore

    def _call_provider(self, payload: SanitizedReviewPayload, settings: Settings) -> GeminiReviewSuggestion:
        client = self.client_factory(settings) if self.client_factory else self._build_client(settings)
        prompt = build_review_prompt(payload)
        attempts = min(settings.gemini_max_retries, 1) + 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                response = self._generate(client, prompt, settings)
                data = self._extract_json(response)
                usage = self._extract_usage(response)
                if usage and not data.get('provider_usage'):
                    data['provider_usage'] = usage
                return self._validate_provider_output(data, payload, settings)
            except ReviewServiceError:
                raise
            except Exception as error:
                last_error = error
                if attempt + 1 < attempts:
                    time.sleep(min(0.25 * (attempt + 1), 0.5))
        log_event(logger, logging.WARNING, 'dataset_review.provider_failed', reason_code='provider_response_invalid', exception_class=type(last_error).__name__ if last_error else 'UnknownError')
        raise ReviewServiceError('provider_response_invalid', 502)

    @staticmethod
    def _build_client(settings: Settings) -> Any:
        try:
            from google import genai  # type: ignore[import-not-found]
        except ImportError as error:
            raise ReviewServiceError('provider_sdk_not_installed', 503) from error
        try:
            return genai.Client(
                api_key=settings.gemini_api_key,
                http_options={'timeout': settings.gemini_request_timeout_seconds * 1000},
            )
        except Exception as error:
            raise ReviewServiceError('provider_client_unavailable', 503) from error

    @staticmethod
    def _generate(client: Any, prompt: str, settings: Settings) -> Any:
        try:
            from google.genai import types  # type: ignore[import-not-found]
            config = types.GenerateContentConfig(
                response_mime_type='application/json',
                temperature=0,
            )
        except ImportError:
            # Dependency-free test doubles can still exercise the complete
            # response-validation path before the optional SDK is installed.
            # The real client is constructed through _build_client, which
            # fails closed when google-genai is unavailable.
            config = {'response_mime_type': 'application/json', 'temperature': 0}
        return client.models.generate_content(model=settings.gemini_model, contents=prompt, config=config)

    @staticmethod
    def _extract_json(response: Any) -> dict[str, Any]:
        if response is None:
            raise ReviewServiceError('empty_provider_response', 502)
        feedback = getattr(getattr(response, 'prompt_feedback', None), 'block_reason', None)
        if feedback:
            raise ReviewServiceError('provider_blocked_response', 502)
        text = getattr(response, 'text', None)
        if not isinstance(text, str) or not text.strip():
            raise ReviewServiceError('empty_provider_response', 502)
        try:
            value = json.loads(text)
        except (TypeError, ValueError) as error:
            raise ReviewServiceError('invalid_provider_json', 502) from error
        if not isinstance(value, dict):
            raise ReviewServiceError('invalid_provider_json', 502)
        return value

    @staticmethod
    def _extract_usage(response: Any) -> dict[str, int] | None:
        usage = getattr(response, 'usage_metadata', None)
        if usage is None:
            return None

        def read(*names: str) -> int | None:
            for name in names:
                value = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
                if isinstance(value, int) and value >= 0:
                    return value
            return None

        values = {
            'input_tokens': read('prompt_token_count', 'input_tokens'),
            'output_tokens': read('candidates_token_count', 'output_tokens'),
            'total_tokens': read('total_token_count', 'total_tokens'),
        }
        return {key: value for key, value in values.items() if value is not None} or None

    @staticmethod
    def _validate_provider_output(data: dict[str, Any], payload: SanitizedReviewPayload, settings: Settings) -> GeminiReviewSuggestion:
        allowed = set(GeminiReviewSuggestion.model_fields)
        unknown = set(data) - allowed
        if unknown:
            raise ReviewServiceError('invalid_provider_schema', 502)
        if 'sample_id' in data and data['sample_id'] != payload.sample_id:
            raise ReviewServiceError('provider_sample_mismatch', 502)
        if 'sanitized_payload_hash' in data and data['sanitized_payload_hash'] != payload.sanitized_payload_hash:
            raise ReviewServiceError('provider_payload_hash_mismatch', 502)
        if 'model_name' in data and data['model_name'] != settings.gemini_model:
            raise ReviewServiceError('provider_model_mismatch', 502)
        if 'prompt_version' in data and data['prompt_version'] != (settings.gemini_prompt_version or PROMPT_VERSION):
            raise ReviewServiceError('provider_prompt_version_mismatch', 502)
        data = dict(data)
        data.update({
            'suggestion_id': data.get('suggestion_id') or f'gemini-{uuid.uuid4().hex}',
            'sample_id': payload.sample_id,
            'model_name': settings.gemini_model,
            'prompt_version': settings.gemini_prompt_version or PROMPT_VERSION,
            'sanitized_payload_hash': payload.sanitized_payload_hash,
            'generated_at': data.get('generated_at') or datetime.now(timezone.utc).isoformat(),
            'provider_usage': data.get('provider_usage') or {},
        })
        try:
            suggestion = GeminiReviewSuggestion.model_validate(data)
        except Exception as error:
            raise ReviewServiceError('invalid_provider_schema', 502) from error
        if suggestion.sample_id != payload.sample_id or suggestion.sanitized_payload_hash != payload.sanitized_payload_hash:
            raise ReviewServiceError('provider_payload_hash_mismatch', 502)
        return suggestion
