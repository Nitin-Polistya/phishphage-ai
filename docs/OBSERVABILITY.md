# Observability

The repository provides privacy-safe, process-local observability. It does not include a durable metrics backend, tracing system, or alerting configuration.

## Request logging

The API emits one JSON `request.complete` event for successful requests and `request.failed` for HTTP failures. Events contain request ID, method, path/endpoint, response status, rounded latency, success, a truncated user agent, and a pseudonymous client identifier. Raw client IPs are not logged. The request ID is accepted from a valid `X-Request-ID` or generated and returned on the response.

Successful CORS preflights are classified as `OPTIONS` and logged at debug level; rejected/error preflights remain visible at info level. They never enter parser/analysis rate limits and never count as analysis requests. A POST analysis request is counted once at the HTTP boundary.

The unified analysis path also emits a debug-level `analysis.timing` event with parser, rules, inference, and total milliseconds. These fields contain no message content and are intended for diagnosing stage-level cold starts without increasing normal production log volume.

Application logs can use the request context for correlation. Error events contain request ID, endpoint, exception class, and a safe generic message. Tracebacks are intentionally omitted so parser/model exception text cannot expose input fragments.

No log or metric field may contain email bodies, parsed fields, MIME content, attachment bytes/names, complete headers, addresses, URLs, cookies, authorization values, API keys, Firebase credentials, model contents, or filesystem paths.

## Runtime endpoints

- `GET /api/v1/health` reports application/environment version, Firebase state, registry/model state, artifact hash metadata, startup, uptime, request counts, analysis counts, and limiter state. It returns 503 in required-ML mode when inference is unavailable.
- `GET /ready` returns 200 only when startup is complete, the registry is valid, and required inference is ready; otherwise it returns 503.
- `GET /metrics` returns JSON process-local counters, separate OPTIONS counters, and safe model metadata plus the startup diagnostic snapshot.

The legacy `/health` endpoint is intentionally minimal. Use `/api/v1/health` for model-aware health checks.

## Counters

Counters include total/successful/failed requests, POST analysis requests, separate OPTIONS/preflight requests, parser and validation failures, rate-limit hits, inference calls, average request/inference latency, startup timestamp, startup completion, and uptime. Warm-up predictions do not increment request or inference counters. Metrics are in memory, reset on process restart, and are not a durable audit trail.

## Startup diagnostics

Startup emits `startup.diagnostics` with privacy-safe timings for settings initialization, registry load, artifact hashing, model deserialization, adapter construction, model warm-up, and total startup. It also reports `ml_required`, `model_configured`, `model_available`, `inference_ready`, `fallback_allowed`, `fallback_active`, `model_id`, `model_version`, `registry_version`, and `artifact_hash_verified`. Hash verification occurs before deserialization. When the registry and configuration are valid, both supported inference paths are prepared before serving requests, which removes the one-time lazy model load from the first request. If `ML_REQUIRED=true`, failed required initialization leaves readiness false and terminates startup.

Firebase is optional. With all Firebase values absent, startup emits an informational `firebase.disabled` event with `reason_code=not_configured`. Partial configuration emits a safe warning, and initialization failures emit a safe error; credentials, configuration values, and filesystem paths are never logged.

Uvicorn access logs default to enabled for development and disabled only when production uses the omitted setting or `UVICORN_ACCESS_LOG=false`. The application’s structured request events remain enabled. If Uvicorn is controlled outside the application, use `--no-access-log` in the production command when duplicate access lines are not wanted.

## Monitoring guidance

An external host should alert on:

- readiness or startup failures;
- registry, artifact, hash, calibration, or inference-integrity failures;
- sustained 5xx/429 responses;
- latency and memory pressure;
- model availability changes;
- unexpected CORS/proxy configuration failures.

Health checks should be sampled or filtered to avoid noisy logs. A multi-instance deployment needs an external aggregation layer because each process has independent counters and rate limits.

## Startup and privacy

Startup emits safe diagnostic fields for environment, API version, selected model ID, registry version, artifact hash, model state, timings, ML-required/fallback state, Firebase-enabled state, limiter state, CORS origin count, access-log policy, and request-size configuration. It does not emit credentials, source URLs, raw input, or filesystem paths.
