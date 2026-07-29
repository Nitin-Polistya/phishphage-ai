# Observability release gate

Status: **Pass locally.**

The successful startup run emitted structured JSON for Firebase-disabled state, startup diagnostics, registry load, artifact verification, model load, warm-up, and request completion. Startup diagnostics showed `fallback_active=false`, `inference_ready=true`, `model_available=true`, `registry_status=ready`, and `uvicorn_access_log=false`.

Health, readiness, and metrics returned 200. Request-completion events included request IDs, endpoint, status, latency, success, preflight state, and a privacy-safe client pseudonym. Synthetic analysis requests completed without raw email content in logs. The existing observability tests cover startup/shutdown events, counters, OPTIONS handling, and privacy-safe logging.

Metrics and rate limits remain process-local and reset on restart; they are not a durable telemetry backend.
