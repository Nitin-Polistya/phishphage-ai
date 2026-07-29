# Environment variable contract

Values below are configuration placeholders, not secrets. The backend reads `apps/api/.env`; the frontend reads `apps/web/.env.local`. A root `.env.example` mirrors the main names for orientation. Do not commit populated environment files.

## Backend

| Variable | Default/requiredness | Purpose |
| --- | --- | --- |
| `APP_NAME` | `PhishShield AI API`; optional | API service label. The public product name is PhishShield AI. |
| `APP_VERSION` | `1.0.0-rc1`; optional | Application release-candidate version returned by health metadata. |
| `ENVIRONMENT` | `development`; set `production` for deployment | Enables production validation/HSTS behavior. |
| `API_V1_PREFIX` | `/api/v1`; optional | Intended API namespace setting. Current router registration is explicitly `/api/v1`; changing this variable alone does not remount routes. |
| `HOST` | command-specific; use `0.0.0.0` in a container | Bind address. |
| `PORT` | `8000`; provider may override | Listening port. |
| `CORS_ORIGINS` | JSON array containing localhost and 127.0.0.1 in the example; required in production | Exact browser-origin JSON array. Wildcard/localhost production values are rejected. |
| `LOG_LEVEL` | `INFO`; optional | Structured log level. |
| `MAX_REQUEST_BYTES` | `2200000`; optional | HTTP body ceiling; accepted range is 1 KiB to 10 MB. |
| `RATE_LIMIT_ENABLED` | `true`; optional | Enables process-local fixed-window limits. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60`; optional | Window duration. |
| `RATE_LIMIT_HEALTH` | `300`; optional | Health/root requests per client/window. |
| `RATE_LIMIT_PARSER` | `60`; optional | Parser requests per client/window. |
| `RATE_LIMIT_ANALYSIS` | `120`; optional | Analysis requests per client/window. |
| `TRUSTED_PROXY_IPS` | empty; provider-dependent | Exact direct peer IPs allowed to supply forwarded client identity. Empty ignores forwarded headers. |
| `ML_REGISTRY_PATH` | `services/ml/models/registry.json`; optional | Registry metadata location. |
| `ML_MODEL_ID` | `phase-c-logistic-regression-v1`; optional | Registry candidate selection. |
| `ML_ARTIFACT_PATH` | unset; deployment/local bundle | Optional artifact override, still contained and hash-checked. |
| `ML_REQUIRED` | `false`; use `true` for deployment | Required mode returns 503/readiness failure when inference is unavailable. |
| `ML_MARGINAL_ALERT_BAND` | `0.08`; optional | Existing narrowly gated fusion band; it does not change the model threshold. |
| `MODEL_ARTIFACT_URL` | unset; deployment only | Private HTTPS source for provisioning. Never publish it. |
| `MODEL_ARTIFACT_TOKEN` | unset; deployment only; secret | Optional bearer token for provisioning. Never log or commit it. |
| `ML_EXPECTED_SHA256` | unset or registry-matching; deployment only | Expected artifact hash. Mismatch aborts provisioning. |
| `MODEL_ARTIFACT_MAX_BYTES` | `10485760` in provisioning code; optional | Provisioning download ceiling. |
| `MODEL_ARTIFACT_TIMEOUT_SECONDS` | `30` in provisioning code; optional | Provisioning timeout. |
| `FIREBASE_PROJECT_ID` | unset; optional | Firebase project identifier. |
| `FIREBASE_CLIENT_EMAIL` | unset; optional secret | Firebase service identity. |
| `FIREBASE_PRIVATE_KEY` | unset; optional secret | Firebase private key; escaped newlines are accepted. |

The complete Firebase credential set is required before the optional SDK initializes. Firebase presence does not add API authentication or authorization.

## Frontend

| Variable | Default/requiredness | Purpose |
| --- | --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` in the example; required for a deployed frontend | Backend origin used by browser fetches. Use HTTPS outside local development. |
| `NEXT_PUBLIC_FIREBASE_API_KEY` | unset; optional | Public Firebase client configuration only if a future frontend integration uses it. |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | unset; optional | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | unset; optional | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | unset; optional | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | unset; optional | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | unset; optional | Public Firebase client configuration. |

Anything prefixed `NEXT_PUBLIC_` is browser-visible. Never use that prefix for service-account credentials, private artifact tokens, or other secrets.
