# Deployment guide

## Current status

This repository contains deployment preparation only. No frontend, backend, model artifact, cloud account, public URL, or production deployment has been used by this phase. The included provider manifests disable automatic deployment. Provider quotas, pricing, capacity, HTTPS smoke tests, and provider-like startup remain unverified.

## Recommended topology

Use a managed Next.js host for `apps/web` and a non-root Docker service for `apps/api`. The frontend receives an exact HTTPS `NEXT_PUBLIC_API_BASE_URL`; the backend sits behind a trusted HTTPS ingress with an exact `CORS_ORIGINS` allowlist. The backend provisions the private model bundle before starting Uvicorn and reports readiness only after registry/model checks pass.

```text
Browser -> managed HTTPS frontend -> trusted HTTPS ingress -> FastAPI Docker service
                                                        -> private model bundle
```

This is a recommendation for a future portfolio deployment, not evidence that a provider has been selected or validated.

## Frontend deployment

From `apps/web`, install from the lockfile and build the Next.js app:

```powershell
npm ci
npm run build
npm start
```

Set `NEXT_PUBLIC_API_BASE_URL` to the backend HTTPS origin at build/runtime according to the host. Do not place backend service credentials in browser-visible variables. `vercel.json` sets the framework/build/install commands and has deployment disabled.

## Backend deployment

The Dockerfile installs `apps/api/requirements.txt`, copies the API and provisioning script, creates a non-root user, exposes port 8000, provisions the model, and runs Uvicorn with a configurable worker count. The intended production command shape is:

```text
python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WEB_CONCURRENCY:-1}
```

The container health check calls `/api/v1/health`. Use `ENVIRONMENT=production`, `ML_REQUIRED=true`, exact `CORS_ORIGINS`, `TRUSTED_PROXY_IPS` only when the provider peer addresses are known, and private model provisioning variables. Do not use reload mode in deployment.

## Provider manifests

- `render.yaml` describes a Docker web service, production environment, exact health path, and private/sync-required model variables. `autoDeploy: false` is explicit.
- `vercel.json` describes the Next.js build/install commands and sets deployment disabled.

These files are inputs for a future operator review. They do not deploy anything by themselves.

## Model provisioning

The private release must contain the registry-compatible pipeline, vectorizer, and feature manifest. `provision_model_artifact.py` requires a private HTTPS source, applies timeout and byte limits, writes a same-directory temporary file, verifies SHA-256, and atomically installs without overwriting an existing artifact. The model manager then rechecks all registry hashes and metadata before deserialization.

Do not publish private artifact URLs or tokens. See [MODEL_ARTIFACT_DISTRIBUTION.md](MODEL_ARTIFACT_DISTRIBUTION.md) and [MODEL.md](MODEL.md).

## HTTPS, CORS, and trusted proxies

TLS redirect and certificate termination belong at the ingress. The API adds HSTS only in production, so `ENVIRONMENT=production` assumes external HTTPS is already guaranteed. Configure exact frontend origins; wildcard, localhost, loopback, and credentialed CORS are not valid production settings. Set `TRUSTED_PROXY_IPS` only to exact ingress peer addresses. With an empty list, forwarded headers are ignored for rate-limit identity.

## Health and readiness

- Provider health check: `/api/v1/health`.
- Deployment readiness: `/ready`, which returns 503 until startup, registry, and required inference checks pass.
- Detailed runtime status: `/api/v1/health`.
- Process-local counters: `/metrics` or `/api/v1/metrics` is not registered; use `/metrics`.

When `ML_REQUIRED=true`, missing or unverified inference returns 503. When false, the API may run with rule-only fallback and explicitly reports ML unavailable.

## Persistence and scaling

Raw email and attachments are not persisted by the API. Logs go to stdout/stderr. The model bundle is a release input; a persistent volume is not required if each release reprovisions it, but provider disk semantics must be verified. Each instance has its own model memory, metrics, and rate limiter. Use a shared limiter/gateway before relying on limits in a multi-instance deployment.

## Monitoring

Monitor readiness failures, startup/model integrity failures, 5xx/429 rates, latency, worker memory, provider health, and artifact hash state. Sample health checks to avoid log noise. Runtime metrics reset on process restart and do not replace a durable telemetry backend.

## Release and rollback

Deploy frontend and backend independently when practical. Roll back to the last known-good application/configuration release. Model rollback selects a previously reviewed registry entry and matching private artifact hash, provisions it as an immutable release, and reruns readiness/security gates. See [ROLLBACK.md](ROLLBACK.md).

## Known tooling limitations

The current evidence records a stalled post-change frontend `npm ci`/build gate, unavailable Docker execution, unverified provider capacity, and browser automation blocked by host `spawn EPERM`. Prior local checks do not substitute for a clean provider-like validation. See [TESTING.md](TESTING.md) and [CI_CD.md](CI_CD.md).
