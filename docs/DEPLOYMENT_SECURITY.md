# Deployment security assumptions

This is the deployment-specific companion to [SECURITY.md](SECURITY.md). It records controls that must be supplied by the hosting environment.

## TLS and ingress

Terminate TLS at a trusted ingress and expose the API externally through HTTPS only. The provider must preserve the original scheme and enforce redirect policy. `ENVIRONMENT=production` enables HSTS (`max-age=31536000; includeSubDomains`), so enabling production mode without guaranteed HTTPS is an operator error.

## CORS and proxy identity

Set `CORS_ORIGINS` to the exact frontend origin(s). Wildcards, localhost, loopback, and credentialed cross-origin requests are not valid production assumptions. Credentials are disabled in the API middleware.

Set `TRUSTED_PROXY_IPS` only to exact ingress peer addresses. The application ignores `X-Forwarded-For` unless the direct peer is trusted; arbitrary forwarded headers cannot choose a rate-limit identity.

## Runtime controls

Keep request-size bounds, no-store API responses, request IDs, safe errors, security headers, CSP, and process-local rate limits enabled. Use a shared gateway or limiter before horizontal scaling. Do not expose the unauthenticated API directly to sensitive organizational mail without an access-control decision.

## Artifact and secret controls

Inject private artifact source/token/hash and Firebase service credentials through provider secret configuration. Do not put them in Docker build arguments, public frontend variables, logs, reports, or public documentation. Provision only reviewed artifacts and require hash verification before readiness.

## Operational verification

Before any deployment, complete a clean container build, private artifact provisioning, readiness check, HTTPS/CORS smoke test, dependency scan, capacity check, and browser security verification. The repository has not completed those provider-specific steps; browser launch is currently blocked by host `spawn EPERM`.
