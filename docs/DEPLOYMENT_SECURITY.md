# Deployment security assumptions

TLS must terminate at the hosting provider or an equivalent trusted ingress.
The backend must receive external HTTPS traffic only through that ingress;
`ENVIRONMENT=production` enables HSTS because HTTPS is then an operational
precondition.

`TRUSTED_PROXY_IPS` must contain only exact proxy addresses supplied by the
provider. With an empty list, the application uses the direct peer address and
ignores `X-Forwarded-For`. Arbitrary forwarded headers are never trusted.

Production CORS is an exact, comma-separated origin allowlist. Wildcards,
localhost, and loopback origins are rejected in production. Credentials are
disabled, and allowed methods/headers are limited by the existing middleware.

The proxy is responsible for TLS redirect policy and preserving the original
scheme. The application supplies HSTS only after HTTPS is guaranteed. Request
IDs, safe error bodies, no-store API responses, CSP, framing protection, and
privacy-safe structured logs remain active.
