# Observability

The repository provides privacy-safe, process-local observability. It does not include a durable metrics backend, tracing system, or alerting configuration.

## Request logging

The API emits one JSON `request.complete` event per completed request to stdout. Events contain request ID, method, path/endpoint, response status, rounded latency, success, a truncated user agent, and a pseudonymous client identifier. Raw client IPs are not logged. The request ID is accepted from a valid `X-Request-ID` or generated and returned on the response.

Application logs can use the request context for correlation. Error events contain request ID, endpoint, exception class, and a safe generic message. Development may include a traceback; production does not.

No log or metric field may contain email bodies, parsed fields, MIME content, attachment bytes/names, complete headers, addresses, URLs, cookies, authorization values, API keys, Firebase credentials, model contents, or filesystem paths.

## Runtime endpoints

- `GET /api/v1/health` reports application/environment version, Firebase state, registry/model state, artifact hash metadata, startup, uptime, request counts, analysis counts, and limiter state. It returns 503 in required-ML mode when inference is unavailable.
- `GET /ready` returns 200 only when startup is complete, the registry is valid, and required inference is ready; otherwise it returns 503.
- `GET /metrics` returns JSON process-local counters and safe model metadata.

The legacy `/health` endpoint is intentionally minimal. Use `/api/v1/health` for model-aware health checks.

## Counters

Counters include total/successful/failed requests, analysis requests, parser and validation failures, rate-limit hits, inference calls, average request/inference latency, startup timestamp, startup completion, and uptime. Metrics are in memory, reset on process restart, and are not a durable audit trail.

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

Startup emits safe diagnostic fields for environment, API version, selected model ID, registry version, artifact hash, ML-required state, Firebase-enabled state, limiter state, CORS origin count, and request-size configuration. It does not emit credentials, source URLs, raw input, or filesystem paths.
