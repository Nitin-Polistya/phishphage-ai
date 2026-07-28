# Screenshot preparation

Screenshots are intentionally placeholders until they are captured from a real local run. Do not fabricate images or edit a capture to imply that the API/model is available.

1. Start FastAPI and Next.js using [DEVELOPMENT.md](DEVELOPMENT.md).
2. Use a 1440x900 viewport for the landing page, Analyze input, and result captures.
3. Use a 390x844 viewport for the mobile Analyze capture.
4. On `/analyze`, use the synthetic built-in example and submit it for the result view.
5. Record the actual Connected/Degraded/Offline state shown by the application.
6. Save reviewed captures under `docs/images/` only after confirming they contain no real email, personal data, secrets, or raw backend errors.

Suggested placeholder names are `landing-page.png`, `analysis-input.png`, `phishing-result.png`, and `mobile-analysis.png`. Add links only after those files exist.
