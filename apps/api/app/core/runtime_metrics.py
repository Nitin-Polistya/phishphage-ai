"""Process-local, privacy-safe runtime counters."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any


class RuntimeMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_monotonic = time.monotonic()
        self._startup_time = datetime.now(timezone.utc).isoformat()
        self._startup_complete = False
        self._startup_diagnostics: dict[str, Any] = {}
        self._total_requests = 0
        self._total_analysis_requests = 0
        self._total_options_requests = 0
        self._successful_options_requests = 0
        self._failed_options_requests = 0
        self._successful_requests = 0
        self._failed_requests = 0
        self._parser_failures = 0
        self._validation_failures = 0
        self._rate_limit_hits = 0
        self._request_latency_total_ms = 0.0
        self._inference_calls = 0
        self._inference_latency_total_ms = 0.0

    def mark_startup_complete(self) -> None:
        with self._lock:
            self._startup_complete = True

    def set_startup_diagnostics(self, diagnostics: dict[str, Any]) -> None:
        with self._lock:
            self._startup_diagnostics = dict(diagnostics)
            self._startup_complete = bool(diagnostics.get('startup_complete', False))

    def startup_diagnostics(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._startup_diagnostics)

    def record_request(self, method: str, path: str, status: int, latency_ms: float) -> None:
        with self._lock:
            self._total_requests += 1
            self._request_latency_total_ms += max(0.0, latency_ms)
            if method.upper() == 'OPTIONS':
                self._total_options_requests += 1
                if status < 400:
                    self._successful_options_requests += 1
                else:
                    self._failed_options_requests += 1
            if method.upper() == 'POST' and (path.endswith('/analyze') or path.endswith('/analysis/preview')):
                self._total_analysis_requests += 1
            if status < 400:
                self._successful_requests += 1
            else:
                self._failed_requests += 1
            if status == 422:
                self._validation_failures += 1
            if path.endswith('/parser/preview') and status >= 400 and status not in {413, 429}:
                self._parser_failures += 1

    def record_rate_limit_hit(self) -> None:
        with self._lock:
            self._rate_limit_hits += 1

    def record_inference(self, latency_ms: float) -> None:
        with self._lock:
            self._inference_calls += 1
            self._inference_latency_total_ms += max(0.0, latency_ms)

    def snapshot(self, model: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            uptime = max(0.0, time.monotonic() - self._started_monotonic)
            payload: dict[str, Any] = {
                'total_requests': self._total_requests,
                'total_analysis_requests': self._total_analysis_requests,
                'options_requests': self._total_options_requests,
                'successful_options_requests': self._successful_options_requests,
                'failed_options_requests': self._failed_options_requests,
                'successful_requests': self._successful_requests,
                'failed_requests': self._failed_requests,
                'parser_failures': self._parser_failures,
                'validation_failures': self._validation_failures,
                'rate_limit_hits': self._rate_limit_hits,
                'model_inference_calls': self._inference_calls,
                'average_inference_latency_ms': round(self._inference_latency_total_ms / self._inference_calls, 3) if self._inference_calls else 0.0,
                'average_request_latency_ms': round(self._request_latency_total_ms / self._total_requests, 3) if self._total_requests else 0.0,
                'startup_time': self._startup_time,
                'startup_complete': self._startup_complete,
                'uptime_seconds': round(uptime, 3),
                'startup_diagnostics': dict(self._startup_diagnostics),
            }
        if model is not None:
            payload['model'] = model
        return payload


runtime_metrics = RuntimeMetrics()
