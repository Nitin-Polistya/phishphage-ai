# Remediation log

1. Captured clean tracked baseline; preserved the pre-existing untracked `reports/` tree.
2. Added `SecurityMiddleware` for request IDs, body limits, rate limits, response headers, no-store API responses, and production HSTS.
3. Restricted CORS to normalized configured origins and minimal methods/headers.
4. Added parser control-character, header-line, MIME-part, attachment, and URL bounds; parser errors no longer echo exception text.
5. Contained model registry and override paths and retained pre-deserialization SHA-256 checks.
6. Removed the Next.js inline theme initialization script and added CSP/security headers.
7. Expanded ignore rules for environment variants, runtime logs, and browser test output.
8. Added synthetic regression tests in `apps/api/tests/test_security_controls.py` and updated the oversized request contract to HTTP 413.
9. Added Chromium-only Playwright configuration and synthetic browser security checks under `apps/web/tests/security/`; execution was blocked before browser launch by host-level process permissions.
