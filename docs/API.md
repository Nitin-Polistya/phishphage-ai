# API reference

The API is a JSON FastAPI service. The examples below use fabricated `example.com` data only. They are examples of shape, not guaranteed live responses. The API has no authentication or authorization in this repository.

## Common behavior

- The default API prefix is `/api/v1`.
- Requests receive an `X-Request-ID` response header. A caller may supply an ID matching `[A-Za-z0-9._-]{1,80}`; otherwise the service generates one.
- API paths return `Cache-Control: no-store`. The legacy root health paths are outside `/api/` and do not receive that middleware cache header.
- The middleware rejects a declared or measured HTTP body larger than `MAX_REQUEST_BYTES` (default 2,200,000 bytes) with HTTP 413.
- Fixed-window rate limits are process-local and default to 300 health requests, 60 parser requests, and 120 analysis requests per client per 60 seconds. HTTP 429 includes `Retry-After`. Limits can be disabled or changed by configuration; they are not coordinated across instances.
- CORS is an exact configured origin list. Credentials are disabled. Allowed methods are `GET`, `POST`, and `OPTIONS`; allowed request headers are `Content-Type`, `Accept`, and `X-Request-ID`.
- Request bodies are not included in logs or error responses. Unhandled errors return a generic HTTP 500 body.

## Endpoint inventory

| Method | Path | Purpose | Rate-limit bucket | Cache |
| --- | --- | --- | --- | --- |
| `GET` | `/` | Legacy service liveness message | health | no explicit cache header |
| `GET` | `/health` | Minimal legacy health response | health | no explicit cache header |
| `GET` | `/ready` | Readiness gate | none | no explicit cache header |
| `GET` | `/metrics` | Process-local metrics | none | no explicit cache header |
| `GET` | `/api/v1/health` | Detailed health and model status | health | `no-store` |
| `POST` | `/api/v1/parser/preview` | Parse and normalize an email | parser | `no-store` |
| `POST` | `/api/v1/analyze` | Raw-email inference contract | analysis | `no-store` |
| `POST` | `/api/v1/analysis/preview` | Mode-aware parser/rules/ML/fusion contract | analysis | `no-store` |

## `GET /`

Purpose: legacy liveness response.

Request body: none.

Response body, HTTP 200:

```json
{
  "message": "PhishPhage AI API is running"
}
```

Response codes: `200`.

Payload limits: none beyond normal HTTP middleware limits; there is no request body.

Rate-limit behavior: default health bucket, 300 requests per client per 60 seconds.

Request ID and cache behavior: `X-Request-ID` is returned. This legacy root path does not receive the `/api/` no-store header.

Security notes: liveness only; it does not prove that the model is ready.

## `GET /health`

Purpose: minimal legacy health response.

Request body: none.

Response body, HTTP 200:

```json
{
  "status": "ok",
  "service": "PhishPhage AI API"
}
```

Response codes: `200`.

Payload limits: none beyond normal middleware limits.

Rate-limit behavior: default health bucket.

Request ID and cache behavior: `X-Request-ID` is returned; no explicit no-store header is added to this legacy path.

Security notes: this is not the model-aware health contract. Use `/api/v1/health` for model state.

## `GET /ready`

Purpose: readiness for a provider health check. Startup must be complete and the registry must be valid. If `ML_REQUIRED=true`, inference must also be ready.

Request body: none.

Response body, HTTP 200:

```json
{
  "status": "ready",
  "service": "PhishPhage AI API",
  "startup_complete": true,
  "registry_valid": true,
  "model_available": true
}
```

Response codes:

- `200` when readiness requirements are satisfied.
- `503` with `{"detail":{"code":"service_not_ready","message":"Service readiness requirements are not satisfied."}}` otherwise.

Payload limits: none beyond normal middleware limits.

Rate-limit behavior: no endpoint bucket is applied to `/ready`.

Request ID and cache behavior: `X-Request-ID` is returned; no explicit no-store header is added to this legacy path.

Security notes: return `503` should be treated as unavailable by a hosting health check. The endpoint exposes only boolean/status metadata and no filesystem paths.

## `GET /metrics`

Purpose: process-local operational counters and safe model metadata.

Request body: none.

Response body, HTTP 200:

```json
{
  "total_requests": 42,
  "total_analysis_requests": 8,
  "successful_requests": 38,
  "failed_requests": 4,
  "parser_failures": 1,
  "validation_failures": 2,
  "rate_limit_hits": 1,
  "model_inference_calls": 8,
  "average_inference_latency_ms": 6.214,
  "average_request_latency_ms": 31.807,
  "startup_time": "2026-01-01T00:00:00+00:00",
  "startup_complete": true,
  "uptime_seconds": 3600.5,
  "model": {
    "loaded": true,
    "model_id": "phase-c-logistic-regression-v1",
    "model_version": "1.0.0",
    "registry_version": "phase_d_registry_v1",
    "artifact_hash": "sha256-redacted-example"
  }
}
```

Response codes: `200`.

Payload limits: none beyond normal middleware limits.

Rate-limit behavior: no endpoint bucket is applied to `/metrics`.

Request ID and cache behavior: `X-Request-ID` is returned; no explicit no-store header is added to this legacy path.

Security notes: counters reset on process restart. Do not treat this endpoint as durable telemetry or an authorization boundary.

## `GET /api/v1/health`

Purpose: detailed application, registry, inference, Firebase, startup, and request-count status. With `ML_REQUIRED=false`, a missing model produces HTTP 200 with `status=degraded`; with `ML_REQUIRED=true`, it produces HTTP 503.

Request body: none.

Response body, HTTP 200 example:

```json
{
  "status": "ok",
  "service": "PhishPhage AI API",
  "firebase": "not_configured",
  "firebase_enabled": false,
  "loaded_model": "phase-c-logistic-regression-v1",
  "model_version": "1.0.0",
  "calibration": "isotonic",
  "deployment_candidate": true,
  "activated": false,
  "pipeline_sha": "sha256-redacted-example",
  "artifact_hash": "sha256-redacted-example",
  "registry_version": "phase_d_registry_v1",
  "registry_status": "ready",
  "registry_loaded": true,
  "artifact_found": true,
  "hash_verified": true,
  "model_available": true,
  "inference_ready": true,
  "reason_code": null,
  "application_version": "1.0.0-rc1",
  "environment": "development",
  "uptime_seconds": 42.1,
  "startup_time": "2026-01-01T00:00:00+00:00",
  "startup_complete": true,
  "request_counts": {"total": 4, "successful": 4, "failed": 0},
  "analysis_counts": {"total": 1, "inference_calls": 1},
  "rate_limiter_enabled": true
}
```

Response codes:

- `200` when the API is available; `status` is `ok` or `degraded`.
- `429` when the health bucket is exhausted.
- `503` with `code=model_unavailable` when `ML_REQUIRED=true` and inference is not ready.

Payload limits: no request body; normal middleware limits still apply.

Rate-limit behavior: default health bucket, 300 requests per client per 60 seconds.

Request ID and cache behavior: `X-Request-ID` and `Cache-Control: no-store` are returned.

Security notes: hashes and IDs are metadata only; the response does not expose local filesystem paths, tokens, or credentials. Firebase status means only that the credential set is configured, not that authorization is active.

## `POST /api/v1/parser/preview`

Purpose: return a normalized parse of raw RFC822 or `.eml` text. It is useful for parser inspection and is not the frontend's primary unified-analysis contract.

Request body:

```json
{
  "raw_email": "From: sender@example.com\nTo: reviewer@example.com\nSubject: Status update\nDate: Thu, 01 Jan 2026 12:00:00 +0000\nMessage-ID: <synthetic-1@example.com>\n\nThe review is complete."
}
```

Response body, HTTP 200:

```json
{
  "subject": "Status update",
  "sender": {"name": null, "address": "sender@example.com"},
  "reply_to": null,
  "recipients": [{"name": "Reviewer", "address": "reviewer@example.com"}],
  "cc": [],
  "date": "Thu, 01 Jan 2026 12:00:00 +0000",
  "message_id": "<synthetic-1@example.com>",
  "body_text": "The review is complete.",
  "body_html": null,
  "body_visible_text": "",
  "headers": {"From": "sender@example.com", "To": "reviewer@example.com", "Subject": "Status update"},
  "extracted_urls": [],
  "url_evidence": [],
  "html_links": [],
  "attachments": []
}
```

Response codes:

- `200` parsed response.
- `400` invalid email input or parser validation failure.
- `413` HTTP body over the global limit.
- `422` Pydantic request-shape failure.
- `429` parser rate limit.
- `500` safe parser failure.

Payload limits: parser email input is at most 2 MiB UTF-8; at most 200 header lines, 998 bytes per header line, 100 MIME parts, 25 attachments, 200 extracted URLs, and 2,048 characters per extracted URL.

Rate-limit behavior: 60 requests per client per default 60-second window.

Request ID and cache behavior: `X-Request-ID` and `Cache-Control: no-store` are returned.

Security notes: attachments are metadata only; HTML is parsed but not rendered; URLs are extracted but never fetched; parser errors are sanitized.

## `POST /api/v1/analyze`

Purpose: compact raw-email inference response.

Request body:

```json
{
  "raw_email": "From: sender@example.com\nTo: reviewer@example.com\nSubject: Account notice\nDate: Thu, 01 Jan 2026 12:00:00 +0000\nMessage-ID: <synthetic-2@example.com>\n\nPlease review the notice through the official website."
}
```

Response body, HTTP 200 example:

```json
{
  "model_id": "phase-c-logistic-regression-v1",
  "model_version": "1.0.0",
  "prediction": "legitimate",
  "probability": 0.21,
  "risk_score": 21,
  "confidence": 0.79,
  "threshold_used": 0.5,
  "feature_families": ["lexical"],
  "signals": {
    "detected_indicators": [],
    "phishing_signals": [],
    "authentication_signals": [],
    "url_indicators": [],
    "urgency_indicators": []
  },
  "recommendations": ["Remain cautious with links, attachments, and requests for sensitive information."],
  "processing_time_ms": 4.2
}
```

Response codes:

- `200` inference response.
- `400` invalid or empty email.
- `413` HTTP body over the global limit.
- `422` request schema failure, including empty or overlong `raw_email`.
- `429` analysis rate limit.
- `503` registry/model unavailable or integrity failure.
- `500` safe inference failure.

Payload limits: `raw_email` is 1 to 2,000,000 characters in the request schema and also subject to the 2 MiB parser and 2,200,000-byte HTTP limits.

Rate-limit behavior: 120 requests per client per default 60-second window.

Request ID and cache behavior: `X-Request-ID` and `Cache-Control: no-store` are returned.

Security notes: the model sees normalized subject/body text. It does not fetch URLs, execute attachments, or validate live sender reputation. A returned prediction supports review and is not a safety guarantee.

## `POST /api/v1/analysis/preview`

Purpose: unified mode-aware analysis used by the current Analyze workspace. It combines parsing, rules, optional ML, decision fusion, evidence completeness, authentication evidence, and freshness metadata.

### Request body

Raw RFC822 mode:

```json
{
  "input_mode": "raw_email",
  "raw_email": "From: sender@example.com\nTo: reviewer@example.com\nSubject: Project update\nDate: Thu, 01 Jan 2026 12:00:00 +0000\nMessage-ID: <synthetic-3@example.com>\n\nThe project update is ready."
}
```

Quick Paste mode:

```json
{
  "input_mode": "quick_paste",
  "sender_name": "Sender",
  "sender_email": "sender@example.com",
  "recipient_name": "Reviewer",
  "recipient_email": "reviewer@example.com",
  "subject": "Project update",
  "body": "The project update is ready."
}
```

`.eml` upload mode uses `input_mode=eml_upload` and places the file text in `raw_email`. The API receives JSON text; multipart upload is not registered.

Request fields:

| Field | Type | Notes |
| --- | --- | --- |
| `input_mode` | `quick_paste`, `raw_email`, or `eml_upload` | Defaults to `raw_email`. |
| `raw_email` | string or null | Required except for Quick Paste; raw modes require at least two recognized source headers. |
| `sender_name`, `recipient_name` | string or null | Maximum 200 characters. |
| `sender_email`, `recipient_email`, `reply_to` | email or null | Parsed as validated email addresses. |
| `subject` | string or null | Maximum 998 characters. |
| `body` | string or null | Required for Quick Paste. |
| `attachments` | array | Maximum 25 metadata records; contents are never accepted. |

### Response body

The response contains these nested objects:

- `parser`: normalized subject, sender, recipients, headers, body text, visible HTML text, URL evidence, HTML anchors, and attachment metadata.
- `rule_analysis`: `classification`, `risk_score`, `confidence`, `signals`, `recommendations`, `engine_version`, engineered features, explanations, and evidence.
- `ml_analysis`: `status`, prediction, legitimate/phishing probabilities, model version, reason, and decision threshold. Unavailable fields are null.
- `decision`: fused classification, risk score, confidence, fusion reason, and whether limited authentication evidence influenced the result.
- `analysis_completeness`: one of `body_text_only`, `structured_fields`, `html_content`, or `complete_raw_email`, with evidence booleans and warning.
- `engine_agreement`: `agreement`, `disagreement`, or `ml_unavailable`.
- Diagnostic fields: raw/adjusted rule score, ML prediction/probability/threshold, final confidence, fusion reason, positive authentication evidence, authentication status, freshness, and stale reason.

Representative response using synthetic data:

```json
{
  "parser": {
    "subject": "Project update",
    "sender": {"name": "Sender", "address": "sender@example.com"},
    "reply_to": null,
    "recipients": [{"name": "Reviewer", "address": "reviewer@example.com"}],
    "cc": [], "date": null, "message_id": null,
    "body_text": "The project update is ready.", "body_html": null,
    "body_visible_text": "", "headers": {}, "extracted_urls": [],
    "url_evidence": [], "html_links": [], "attachments": []
  },
  "rule_analysis": {
    "classification": "safe", "risk_score": 0, "confidence": 0.8,
    "signals": [], "recommendations": [], "engine_version": "rules-v3.1.0",
    "engineered_features": {}, "feature_explanations": {}, "feature_evidence": {}
  },
  "ml_analysis": {
    "status": "available", "prediction": "legitimate",
    "phishing_probability": 0.21, "legitimate_probability": 0.79,
    "model_version": "1.0.0", "reason": null, "decision_threshold": 0.5
  },
  "decision": {
    "classification": "safe", "risk_score": 21, "confidence": 0.79,
    "presentation_state": "needs_review", "safe_verdict_allowed": false,
    "fusion_reason": "Rule and ML evidence are aligned.",
    "limited_authentication_evidence": false
  },
  "recommendations": ["Remain cautious with links, attachments, and requests for sensitive information."],
  "analysis_completeness": {
    "state": "structured_fields", "limited_evidence": true,
    "warning": "Limited evidence: some structured fields were available, but complete raw headers and HTML destinations were not.",
    "has_from_header": false, "has_reply_to": false, "has_return_path": false,
    "has_authentication_results": false, "has_spf_result": false,
    "has_dkim_result": false, "has_dmarc_result": false,
    "has_html_source": false, "has_real_href_destinations": false,
    "has_attachment_metadata": false, "has_complete_raw_headers": false
  },
  "engine_agreement": "agreement",
  "rule_raw_score": 0, "rule_adjusted_score": 0,
  "ml_prediction": "legitimate", "ml_phishing_probability": 0.21,
  "ml_threshold": 0.5, "final_decision_confidence": 0.79,
  "rule_ml_agreement": "agreement", "fusion_reason": "Rule and ML evidence are aligned.",
  "positive_authentication_evidence": [], "authentication_evidence_status": "unavailable",
  "analysis_freshness": "current", "stale_reason": null
}
```

Response codes:

- `200` unified analysis, including a rule-only fallback when optional ML is unavailable.
- `400` invalid raw/RFC822 input or missing Quick Paste body.
- `413` HTTP body over the global limit.
- `422` request schema failure.
- `429` analysis rate limit.
- `503` when `ML_REQUIRED=true` and the model cannot be loaded or verified.
- `500` safe internal pipeline error.

Payload limits: the global HTTP limit is 2,200,000 bytes; raw parser input is 2 MiB; Quick Paste body is checked against the same 2 MiB email limit; attachment metadata is capped at 25 items; filenames and content types are capped at 255 characters; names at 200; subject at 998. The parser also bounds MIME parts, header lines, and extracted URLs as described above.

Rate-limit behavior: 120 requests per client per default 60-second window.

Request ID and cache behavior: `X-Request-ID` and `Cache-Control: no-store` are returned.

Security notes: the pipeline never renders HTML, contacts URL destinations, executes attachments, or treats missing authentication as failure. Incomplete evidence is presented as needs review and cannot be exported as a current safe verdict. The response can contain parsed header/address metadata; callers must protect it as sensitive data.

## Decision-safety response metadata

`/api/v1/analyze` preserves the raw rule score, adjusted rule score, ML probability, ML threshold, and pre-floor score. It also returns `fusion_policy_version` (`asymmetric-safety-v1`), `post_floor_score`, `applied_floor`, `applied_floor_reason`, `evidence_families`, `high_confidence_rule_evidence`, `protective_evidence`, and `disagreement_resolution`. The decision remains explainable: the floor can raise the final presentation score and classification when independent rule families corroborate a high-confidence threat, but never changes the ML probability, threshold, calibration, model artifact, or registry metadata.

Parsed HTML metadata includes actionable HTTP URL counts, tracking-pixel counts, source types, and privacy-safe normalized domains. `mailto:` anchors are represented as destination domains, recipient counts, action type, and whether the destination is user-actionable; full mailbox addresses are not returned. Authentication is explicit (`passed`, `failed`, `inconclusive`, `missing`, `unavailable`, `malformed`, or `conflicting`) and is not inferred from a bare authentication token.

Legacy records with no fusion policy are migrated with `fusionPolicyVersion: "unknown"`; their original classification and raw fields are preserved, while safe eligibility is blocked until a fresh current-policy rescan. These fields never include raw bodies or full headers.

## Error shape

Common middleware errors use:

```json
{
  "detail": {
    "code": "rate_limit_exceeded",
    "message": "Too many requests."
  }
}
```

Validation errors use HTTP 422 with a list of safe locations/messages. Error messages are not a substitute for request IDs; include the returned `X-Request-ID` when reporting an operational failure.
