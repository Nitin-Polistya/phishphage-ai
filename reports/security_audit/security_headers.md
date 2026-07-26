# Security headers

Backend middleware emits `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`, `X-Frame-Options: DENY`, `Content-Security-Policy` with `frame-ancestors 'none'`, request-specific `X-Request-ID`, and `Cache-Control: no-store` for API routes. HSTS is emitted only when `ENVIRONMENT=production`.

Next.js headers add CSP, nosniff, no-referrer, permissions policy, and frame denial. The CSP permits only same-origin scripts, configured API-origin connections, and inline styles required by the existing rendering stack. User email HTML is not rendered as HTML.
