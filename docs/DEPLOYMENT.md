# Deployment guide

## Recommended topology

Host the Next.js frontend on Vercel or an equivalent managed Next.js host and
the FastAPI backend as a single non-root Docker service on Render or an
equivalent container host. Provision the approved model artifact privately at
startup, verify its SHA-256, then start Uvicorn with one worker initially.

Build the frontend with `npm ci` and `npm run build`. Start it with `npm start`
and provide `NEXT_PUBLIC_API_BASE_URL` at build/runtime according to the host.
Start the backend with the container command or:

```text
python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WEB_CONCURRENCY:-1}
```

Set `ENVIRONMENT=production`, `ML_REQUIRED=true`, exact `CORS_ORIGINS`, and the
private artifact provisioning variables. The health route is
`/api/v1/health`; readiness is represented by `inference_ready` and returns
503 when ML is required but unavailable.

No deployment is performed by this repository configuration. `autoDeploy` is
disabled in the included provider manifest.
