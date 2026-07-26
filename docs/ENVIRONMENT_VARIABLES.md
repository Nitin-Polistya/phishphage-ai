# Environment variable contract

This document defines deployment inputs. Example values are placeholders only;
credentials and private artifact URLs must be supplied by the hosting provider.

## Backend

| Variable | Required | Safe default | Secret | Purpose and failure behavior |
|---|---:|---|---:|---|
| `APP_NAME` | no | `PhishPhage AI API` | no | Service label. |
| `APP_VERSION` | no | `0.1.0` | no | Release label. |
| `ENVIRONMENT` | no | `development` | no | `production` enables HSTS and production validation. |
| `API_V1_PREFIX` | no | `/api/v1` | no | API namespace contract. |
| `HOST` | no | command-specific | no | Production command should use `0.0.0.0`. |
| `PORT` | no | `8000` | no | Hosting-assigned listening port. |
| `LOG_LEVEL` | no | `INFO` | no | Structured stdout severity. |
| `CORS_ORIGINS` | yes in production | localhost development origin | no | Comma-separated exact origins; wildcard and localhost production origins are rejected. |
| `TRUSTED_PROXY_IPS` | provider-dependent | empty | no | Exact trusted proxy addresses; empty means forwarded headers are ignored. |
| `RATE_LIMIT_ENABLED` | no | `true` | no | Enables process-local fixed-window limits. |
| `RATE_LIMIT_WINDOW_SECONDS` | no | `60` | no | Rate-limit window. |
| `RATE_LIMIT_HEALTH` | no | `300` | no | Health request limit per client/window. |
| `RATE_LIMIT_PARSER` | no | `60` | no | Parser request limit per client/window. |
| `RATE_LIMIT_ANALYSIS` | no | `120` | no | Analysis request limit per client/window. |
| `MAX_REQUEST_BYTES` | no | `2200000` | no | HTTP body ceiling. |
| `ML_REQUIRED` | no | `false` | no | In production use `true`; readiness and analysis fail safely if inference is unavailable. |
| `ML_REGISTRY_PATH` | no | registry path | no | Approved registry location; paths remain inside the model directory. |
| `ML_MODEL_ID` | no | approved candidate ID | no | Registry selection only; must match an existing compatible candidate. |
| `ML_ARTIFACT_PATH` | deployment | registry artifact path | no | Provisioned artifact destination inside the approved model directory. |
| `ML_MARGINAL_ALERT_BAND` | no | `0.08` | no | Existing alert-band setting; do not change without model review. |
| `MODEL_ARTIFACT_URL` | deployment | unset | no | HTTPS private artifact source used only by the provisioning command. |
| `MODEL_ARTIFACT_TOKEN` | deployment | unset | yes | Optional bearer token; never logged. |
| `ML_EXPECTED_SHA256` | deployment | registry hash | no | Fixed artifact hash; mismatch aborts provisioning. |
| `MODEL_ARTIFACT_MAX_BYTES` | no | `10485760` | no | Download ceiling. |
| `MODEL_ARTIFACT_TIMEOUT_SECONDS` | no | `30` | no | Download timeout. |
| `FIREBASE_PROJECT_ID` | optional | unset | no | Firebase is disabled when the complete credential set is absent. |
| `FIREBASE_CLIENT_EMAIL` | optional | unset | yes | Firebase service identity. |
| `FIREBASE_PRIVATE_KEY` | optional | unset | yes | Firebase private key; escaped newlines are accepted. |

## Frontend

| Variable | Required | Safe default | Secret | Purpose and failure behavior |
|---|---:|---|---:|---|
| `NEXT_PUBLIC_API_BASE_URL` | yes in production | unset | no | Exact HTTPS backend origin. Invalid or missing values make API calls unavailable. |
| `NEXT_PUBLIC_FIREBASE_API_KEY` | optional | unset | no | Public Firebase client configuration only if Firebase is introduced. |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | optional | unset | no | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | optional | unset | no | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | optional | unset | no | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | optional | unset | no | Public Firebase client configuration. |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | optional | unset | no | Public Firebase client configuration. |

No service-account credential may use a `NEXT_PUBLIC_` name.
