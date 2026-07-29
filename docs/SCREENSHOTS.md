# Screenshot preparation

Screenshots are intentionally placeholders until they are captured from a real local run. Do not fabricate images or edit a capture to imply that the API/model is available.

The complete Phase I.6 capture matrix is [SCREENSHOT_PLAN.md](SCREENSHOT_PLAN.md). It covers the landing page, dashboard, all analyzer input modes, results, decision safety, indicators, history, reports, settings, Swagger, health/readiness, and architecture.

Before a capture:

1. Start FastAPI and Next.js using [DEVELOPMENT.md](DEVELOPMENT.md).
2. Use the planned viewport and theme for the route.
3. Use only the synthetic fixtures under [assets/demo/](assets/demo/).
4. Record the actual Connected/Degraded/Offline and model/readiness state shown by the application.
5. Save reviewed captures under [assets/screenshots/](assets/screenshots/) only after confirming they contain no real email, personal data, secrets, raw backend errors, or local paths.
6. Apply [PORTFOLIO_ASSET_CHECKLIST.md](PORTFOLIO_ASSET_CHECKLIST.md) and add links only after each file exists.
