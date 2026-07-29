# API contract gate

Status: **Pass by route/schema review and full backend test coverage.**

Registered/documented routes remain:

| Method | Path | Status |
| --- | --- | --- |
| GET | `/` | Documented legacy liveness |
| GET | `/health` | Documented legacy health |
| GET | `/ready` | Documented readiness |
| GET | `/metrics` | Documented process-local metrics |
| GET | `/api/v1/health` | Documented detailed health/model status |
| POST | `/api/v1/parser/preview` | Documented parser preview |
| POST | `/api/v1/analyze` | Documented raw-email inference contract |
| POST | `/api/v1/analysis/preview` | Documented unified analysis/fusion contract |

The API documentation covers methods, request/response schemas, status codes, payload limits, rate limits, request IDs, health/readiness/metrics, parser preview, and both analysis contracts. API v1 remains unchanged. Application version metadata changed only from `0.1.0` to `1.0.0-rc1`; model/API compatibility values remain separate.
