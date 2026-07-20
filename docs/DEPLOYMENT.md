# Deployment preparation

This repository has not been deployed. This document describes preparation only.

## Frontend: Vercel

- Root directory: `apps/web`.
- Build command: `npm run build`.
- Output: Next.js default build output.
- Required environment variable: `NEXT_PUBLIC_API_BASE_URL=https://<api-host>`.
- Configure the production API origin before deploying the frontend.
- Use HTTPS and verify browser requests reach `/api/v1/health` and `/api/v1/analyze`.

## Backend: Render (example compatible provider)

- Root directory: repository root.
- Build command: install the API environment/dependencies according to the provider's Python setup.
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT --app-dir apps/api`.
- Provide the API's environment variables, including `CORS_ORIGINS` for the deployed frontend origin.
- Provide the inactive model artifact, vectorizer, feature manifest, and registry at the paths referenced by `services/ml/models/registry.json` (or use a mounted artifact directory without changing hashes).

## Verification checklist

- HTTPS terminates correctly.
- `GET /api/v1/health` reports the expected pipeline SHA and `activated=false` until an explicit future release decision.
- `POST /api/v1/analyze` returns the documented response.
- CORS allows only the frontend origin; do not combine wildcard origins with credentials.
- Cold-start model loading is measured and accepted.
- No secrets, raw email, or generated local reports are committed.
- Rollback restores the prior registry and matching artifact set as an atomic change.

No deployment, activation, or production smoke test was performed in Phase F.
