# Residual risks

- API endpoints remain unauthenticated; deploy behind an appropriate access-control boundary before exposing sensitive workloads.
- Rate limiting is bounded and configurable but process-local; use a trusted shared gateway/store for multiple instances.
- Firebase initialization does not imply user authentication or authorization; no Firebase endpoint is exposed and authorization remains unimplemented.
- Joblib/Pickle artifacts require trusted provenance and controlled filesystem permissions.
- `pip-audit` was unavailable locally and must run in the release environment.
- HSTS and trusted-proxy behavior depend on correct production deployment configuration.
