# Local development guide

## Prerequisites

- Windows PowerShell.
- Python 3.11 or newer.
- Node.js and npm compatible with the checked-in lockfile.
- Git.
- Optional: VS Code, with the Python and Pylance extensions.
- Optional: a locally provisioned model bundle for ML-enabled runs.

## Windows setup

From the repository root:

```powershell
py -3.11 -m venv apps\api\.venv
.\apps\api\.venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt
```

For the ML research package, use its own environment or the API environment only when the installed dependencies satisfy the requested script:

```powershell
.\apps\api\.venv\Scripts\python.exe -m pip install -r services\ml\requirements.txt
```

The repository's current VS Code settings set `python.terminal.activateEnvironment` to `false` and exclude `node_modules`, `.next`, caches, reports, ML data, and ML artifacts from Pylance analysis. Because `.vscode/` is ignored, copy that setting into a personal workspace configuration if needed.

## Environment files

```powershell
Copy-Item apps\api\.env.example apps\api\.env
Copy-Item apps\web\.env.example apps\web\.env.local
```

Keep Firebase and provisioning secrets empty for ordinary local work. The default backend runs with optional ML fallback; do not paste real sensitive mail into a shared or public environment.

## Backend startup

```powershell
.\apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir apps/api
```

The API listens on `http://localhost:8000`. Development defaults to `UVICORN_ACCESS_LOG=true`; use `/api/v1/health` to inspect registry/model status, `/ready` to inspect the readiness gate, and `/metrics` for process-local counters and startup timings.

## Frontend startup

In a second terminal:

```powershell
cd apps\web
npm ci
Copy-Item .env.example .env.local
npm run dev
```

The frontend listens on `http://localhost:3000`. Set `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000` for local API calls.

## Production-mode local run

Build the frontend and run it without the development server:

```powershell
cd apps\web
npm run build
npm start
```

Run the backend without reload and with a container-like bind address/port:

```powershell
$env:ENVIRONMENT='production'
$env:HOST='127.0.0.1'
$env:PORT='8000'
$env:ML_REQUIRED='true'
$env:UVICORN_ACCESS_LOG='false'
.\apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --app-dir apps/api
```

The application keeps structured request/error/startup logs enabled. `UVICORN_ACCESS_LOG=false` suppresses duplicate Uvicorn access lines; the equivalent CLI flag is `--no-access-log` when the server command is managed externally.

Production mode assumes HTTPS at an ingress; local HTTP is for validation only. Do not interpret a local run as a deployment.

## Model artifact setup

The registry is tracked, but model binaries/vectorizers/manifests are ignored. Provision a reviewed local bundle under the approved model directory, or leave `ML_REQUIRED=false` to exercise rule-only fallback. Validate provisioning configuration without a network request:

```powershell
.\apps\api\.venv\Scripts\python.exe apps\api\scripts\provision_model_artifact.py --dry-run
```

Do not invent a model, retrain, edit the registry, alter a threshold, or copy a private artifact URL into documentation as part of ordinary development.

## Test commands

Backend:

```powershell
.\apps\api\.venv\Scripts\python.exe -m pytest -q apps/api/tests
.\apps\api\.venv\Scripts\python.exe -m compileall apps/api/app apps/api/scripts services/ml/src
.\apps\api\.venv\Scripts\python.exe -m pip check
```

Frontend:

```powershell
cd apps\web
npm test
npx --no-install tsc --noEmit
npm run lint
npm run build
npm audit
cd ..\..
```

Research scripts under `services/ml/scripts` require the corresponding data boundary and review gate. They are not normal application tests and must not be used to retrain or promote a model without a separate approval.

## Linting, type checking, and formatting

The frontend has `npm run lint`; TypeScript uses `npx --no-install tsc --noEmit`. There is no checked-in Black command or backend formatter script in the current manifests. If a local Black extension is used, format only the intended files and review `git diff --check` afterward. If the Black formatter or Python language server becomes stuck after an environment change, restart the VS Code Python extension/language server and open a fresh terminal; do not use formatting as a reason to rewrite unrelated files.

## Git workflow

Create a focused branch, preserve unrelated local changes, run relevant tests, inspect the diff, and document any environment limitation. Do not commit automatically from an agent task. Never commit `.env`, raw email, model binaries, dataset files, credentials, browser traces, or generated local reports unless the repository explicitly tracks a sanitized report.

## Common Windows issues

### `spawn EPERM` or access denied

This usually indicates host process policy, endpoint security, or a stale child process. It affects Node child processes and Playwright in the recorded environment. Check running `node`, `python`, browser, and dev-server processes; stop only the process you own; retry from a fresh terminal. If browser launch remains blocked, report the exact error and do not claim browser tests passed.

### Playwright cannot launch

The browser security suite requires a Chromium child process and a running frontend/API. The current host has rejected both Playwright worker/browser launch and direct Chrome headless launch with `spawn EPERM`/access denied. Static tests may still run, but they do not replace interactive verification.

### npm command stalls

Use `npm ci` from `apps/web` and check that no unrelated npm process holds the tree. Do not change the lockfile to work around a timeout. Record the command, duration, and output limitation.

### Black formatter restart

Restart the Python language server/Black extension and VS Code terminal after changing virtual environments. Confirm the selected interpreter is `apps/api/.venv` and rerun only the targeted formatter.

### Pylance is slow or noisy

Keep the workspace exclusions for `node_modules`, `.next`, caches, reports, ML data, and ML artifacts. Pylance does not need to index generated data or model bundles.

### Virtual environment auto-activation

The current personal VS Code setting disables automatic terminal activation. Use the explicit interpreter path in the commands above, or enable auto-activation in a personal workspace setting if that is your preference. Always verify with `Get-Command python` before running a research script.

## Troubleshooting checklist

1. Confirm the current directory is the repository root.
2. Confirm the API virtual environment interpreter exists and imports dependencies.
3. Inspect `/api/v1/health` and `/ready` before debugging frontend output.
4. Verify `NEXT_PUBLIC_API_BASE_URL` and exact development CORS origin.
5. Use synthetic `example.com` messages only.
6. Check request IDs in safe server logs.
7. Run `git diff --check` and `git status --short` before handoff.
