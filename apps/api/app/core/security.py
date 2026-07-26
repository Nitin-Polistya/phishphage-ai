"""Small, dependency-free HTTP controls for the API boundary."""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_ID_RE = re.compile(r'^[A-Za-z0-9._-]{1,80}$')


class FixedWindowLimiter:
    def __init__(self, window_seconds: int, limits: dict[str, int], max_keys: int = 10_000) -> None:
        self.window_seconds = window_seconds
        self.limits = limits
        self.max_keys = max_keys
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, category: str, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            if len(self._events) >= self.max_keys and (category, key) not in self._events:
                return False, self.window_seconds
            events = self._events[(category, key)]
            while events and events[0] <= window_start:
                events.popleft()
            limit = self.limits.get(category)
            if limit is None:
                return True, 0
            if len(events) >= limit:
                return False, max(1, int(events[0] + self.window_seconds - now))
            events.append(now)
            return True, 0


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings) -> None:
        super().__init__(app)
        self.settings = settings
        self.limiter = FixedWindowLimiter(settings.rate_limit_window_seconds, {
            'health': settings.rate_limit_health,
            'parser': settings.rate_limit_parser,
            'analysis': settings.rate_limit_analysis,
        })

    def _client_key(self, request: Request) -> str:
        peer = request.client.host if request.client else 'unknown'
        if peer in self.settings.trusted_proxy_ips:
            forwarded = request.headers.get('x-forwarded-for', '').split(',')[0].strip()
            if forwarded and REQUEST_ID_RE.fullmatch(forwarded):
                return forwarded
        return peer

    @staticmethod
    def _category(path: str, method: str) -> str | None:
        if path.endswith('/health') or path == '/':
            return 'health'
        if method == 'POST' and path.endswith('/parser/preview'):
            return 'parser'
        if method == 'POST' and (path.endswith('/analysis/preview') or path.endswith('/analyze')):
            return 'analysis'
        return None

    async def dispatch(self, request: Request, call_next):
        supplied_id = request.headers.get('x-request-id', '')
        request_id = supplied_id if REQUEST_ID_RE.fullmatch(supplied_id) else str(uuid.uuid4())
        request.state.request_id = request_id

        content_length = request.headers.get('content-length')
        if content_length and (not content_length.isdigit() or int(content_length) > self.settings.max_request_bytes):
            response = JSONResponse({'detail': {'code': 'payload_too_large', 'message': 'Request payload is too large.'}}, status_code=413)
            response.headers['Retry-After'] = '0'
            response.headers['X-Request-ID'] = request_id
            return response
        if request.method in {'POST', 'PUT', 'PATCH'}:
            body = await request.body()
            if len(body) > self.settings.max_request_bytes:
                response = JSONResponse({'detail': {'code': 'payload_too_large', 'message': 'Request payload is too large.'}}, status_code=413)
                response.headers['X-Request-ID'] = request_id
                return response

        category = self._category(request.url.path, request.method)
        if self.settings.rate_limit_enabled and category:
            allowed, retry_after = self.limiter.allow(category, self._client_key(request))
            if not allowed:
                response = JSONResponse({'detail': {'code': 'rate_limit_exceeded', 'message': 'Too many requests.'}}, status_code=429)
                response.headers['Retry-After'] = str(retry_after)
                response.headers['X-Request-ID'] = request_id
                return response

        response = await call_next(request)
        response.headers['X-Request-ID'] = request_id
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        if self.settings.environment.lower() == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
