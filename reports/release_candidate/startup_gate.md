# Production-style local startup gate

Status: **Pass with corrected local invocation; original root command needs context correction.**

Successful validation used:

```powershell
$env:CORS_ORIGINS='["http://localhost:3000","http://127.0.0.1:3000"]'
$env:UVICORN_ACCESS_LOG='false'
$env:ML_REQUIRED='true'
.\apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir apps/api --host 127.0.0.1 --port 8000
```

Results:

- Startup completed with Firebase disabled as an informational state.
- Model hash verified, model loaded, warm-up completed, and fallback inactive.
- `application_version=1.0.0-rc1`, model version `1.0.0`, registry `phase_d_registry_v1`.
- `/api/v1/health`, `/ready`, `/metrics`, and `/docs` returned HTTP 200 in the successful logged run.
- Synthetic safe and phishing analysis POSTs returned HTTP 200.
- Direct pipeline result: safe fixture was safe/0 and safety-eligible; phishing fixture was phishing/100 with the safety floor applied.
- Process was stopped after validation; no service was left running.

The first attempted command omitted `--app-dir apps/api` while starting from the repository root and failed with `ModuleNotFoundError: app`. The container command remains valid because its Dockerfile sets `PYTHONPATH=/app/apps/api`; local root instructions must retain `--app-dir apps/api` or set `PYTHONPATH`.

The original comma-separated CORS environment value also failed Pydantic settings parsing when supplied as a process environment variable. The example now uses a JSON array, which was the successful release-style configuration.
