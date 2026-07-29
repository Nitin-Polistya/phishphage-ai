# Security architecture and operating assumptions

This document describes controls present in the repository. It is not a claim that an Internet deployment is secure by default. The API is unauthenticated, and provider TLS, access control, capacity, and secrets configuration remain deployment responsibilities.

## Threat model summary

The primary attacker controls email text, headers, HTML, URLs, MIME structure, and attachment filenames. A remote client can send requests to the frontend/API boundary. A deployment operator controls environment variables and model release inputs. Assets include raw email in memory, parsed evidence, browser-local records, model artifacts, registry integrity metadata, credentials, generated reports, and service availability.

Trust boundaries are browser to frontend, frontend to FastAPI, FastAPI to parser/analyzers, pipeline to model artifact, browser to local storage, optional Firebase, and deployment platform to secrets/artifacts.

## Request-size and parser safety

The middleware enforces `MAX_REQUEST_BYTES` (default 2,200,000 bytes, bounded by configuration). The parser enforces a 2 MiB UTF-8 email limit, maximum 100 MIME parts, 25 attachment metadata records, 200 header lines, 998 bytes per header line, 200 extracted URLs, and 2,048 characters per extracted URL. Request schema limits also cap Quick Paste names at 200 characters, subjects at 998, attachment filenames/content types at 255, and attachment records at 25.

Malformed headers, empty input, NUL characters, copied display text in raw modes, excessive structure, and invalid request shapes fail safely. Attachment contents are not saved or executed. Parser errors do not echo exception details into client responses.

## MIME and HTML safety

Email is parsed as untrusted data. HTML is parsed for visible text, anchors, forms, metadata, CSS resources, tracking pixels, and URL evidence, but is never rendered. URLs are never fetched, resolved, opened, or submitted. The domain helper uses a local Public Suffix List snapshot with network fetching disabled. MIME parts are bounded and only attachment metadata is returned.

These controls reduce SSRF and parser abuse risk; they do not make arbitrary email safe to open elsewhere.

## SSRF prevention

No API analysis code makes outbound requests based on a submitted URL. The frontend renders destinations as non-clickable text. Domain comparison is offline. The deployment artifact provisioner is a separate operator-controlled HTTPS download path and must not be supplied attacker-controlled URLs; it applies timeout, size, path, and hash checks.

## XSS and browser protections

React renders evidence as text and the frontend does not use submitted HTML as markup. Report exports HTML-escape values and CSV exports protect formula-like cells. The Next.js response headers include:

- `Content-Security-Policy` with same-origin scripts, no objects, no framing, and an explicit API connect origin;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `Permissions-Policy` disabling camera, microphone, and geolocation;
- `X-Frame-Options: DENY`.

The API adds a stricter data-only CSP, `Cache-Control: no-store` for `/api/` responses, and production HSTS. The browser security audit did not complete interactive launch because the host rejected browser child processes with `spawn EPERM`/access denied. No interactive browser-security pass is claimed.

## CORS and request IDs

`CORS_ORIGINS` is normalized as an exact comma-separated allowlist. Wildcards and localhost/loopback origins are rejected in production. Credentials are disabled, and methods/headers are limited to the registered contract. Each request gets a validated caller ID or generated UUID-like ID in `X-Request-ID`; the ID is available for safe log correlation.

## Rate limiting and availability

The fixed-window limiter defaults to 300 health, 60 parser, and 120 analysis requests per client per 60-second window. It is process-local, configurable, and returns HTTP 429 with `Retry-After`. It is not a distributed defense. A horizontally scaled deployment needs a shared gateway/store or equivalent coordinated control. Request and MIME bounds reduce memory/CPU amplification but do not guarantee availability.

## Safe error handling and privacy-safe logging

Production exception responses use generic messages. Development may include a server traceback in logs; production does not. Structured logs include request ID, method, path, status, latency, success, a truncated user agent, and a pseudonymous client identifier derived from the client key. Logs and metrics exclude email bodies, parsed fields, headers, addresses, URLs, attachments, cookies, authorization values, API keys, Firebase credentials, model contents, and local filesystem paths.

Runtime counters are in memory and reset on restart. They are useful for local/provider health integration but are not durable audit logs.

## Model artifact security

The registry is the source of truth for model ID, version, threshold, calibration, activation state, compatibility, and hashes. The model manager keeps registry and artifact paths under the approved model directory and verifies pipeline, vectorizer, and feature-manifest hashes before Joblib deserialization. It validates model metadata, class ordering, threshold, finite probability shape, and inactive state.

Joblib/Pickle can execute code while loading a malicious artifact. Only a reviewed private artifact bundle may be provisioned. Model binaries are ignored by Git and are not public repository files. A hash is integrity evidence, not proof that the artifact is semantically safe.

## Secret handling

Service credentials belong in provider secret configuration or local ignored `.env` files. Never commit Firebase private keys, artifact bearer tokens, or raw private artifact URLs. `NEXT_PUBLIC_` variables are browser-visible and must never contain service-account credentials. The provisioner is designed not to log tokens or source URLs.

## Firebase status

Firebase Admin SDK is optional. Missing credentials leave the service running with `firebase=not_configured`. Present credentials only initialize an SDK client; the current repository does not enforce user authentication, authorization, tenancy, or Firebase security rules around analysis data. Firebase must not be described as an active authorization control.

## Dependency-security posture

Python and Node dependencies are constrained by the checked-in requirement/package manifests and lockfile. Backend tests include security-control and model-integrity coverage; frontend tests include serialization/report checks. `npm audit` and `pip check` are validation gates. The recorded security audit notes that local `pip-audit` tooling was unavailable; therefore no pip vulnerability-scan pass is claimed. Dependency findings must be reviewed separately from application tests.

## Residual risks

- No API authentication or authorization.
- Process-local rate limiting and metrics do not coordinate across workers.
- Trusted Joblib/Pickle remains executable at load time.
- Provider TLS, trusted proxy addresses, exact production CORS, secrets, access control, resource limits, and logging retention are deployment assumptions.
- Browser automation and interactive security verification remain inconclusive in the current host.
- Model false negatives, false positives, source bias, and distribution shift remain material.
- Optional Firebase has no authorization boundary.

## Supported assumptions

The supported security posture assumes synthetic or otherwise authorized email, a trusted deployment operator, an HTTPS ingress, exact frontend/API origin configuration, private reviewed model artifacts, no direct Internet exposure without access-control review, and human review of all high-impact decisions. The repository does not support using a result as an automated allow/block guarantee.

## Vulnerability reporting and responsible disclosure

### Decision-safety policy

The UI and exports prioritize re-scan required, unable to verify, and needs review above phishing/suspicious/safe labels. The safety layer deduplicates evidence by identity, routing, authentication, action, and infrastructure families. High-confidence corroboration can apply a bounded 80–82 floor; moderate corroboration can apply a 60-point suspicious floor. An explicit aligned authentication result and official claimed domain are protective only when no stronger mismatch evidence exists. Authentication tokens are not passes: only parseable explicit results are labeled passed or failed. `mailto:` addresses are reduced to normalized destination domains and action metadata, and tracking pixels are classified as non-actionable supporting evidence. No network lookup, DNS/WHOIS, model retraining, threshold change, or numeric score fabrication is used.

Do not put real email, credentials, personal data, active malicious URLs, attachment files, or exploit payloads in a public issue. Use a private repository security advisory when available. If no private channel exists, open a minimal public issue requesting a private reporting channel and provide only a sanitized description, affected component/route, reproducible synthetic input, expected behavior, observed behavior, and tool versions. Allow maintainers reasonable time to validate and remediate before public disclosure. Do not contact unrelated third parties using information found in a sample.
