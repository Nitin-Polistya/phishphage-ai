# Portfolio asset capture checklist

## Environment

- [ ] Clean browser profile.
- [ ] No unrelated tabs.
- [ ] No personal history, bookmarks, autofill, or notifications.
- [ ] Synthetic subject and sender.
- [ ] Synthetic fixture from `docs/assets/demo/`.
- [ ] Correct project name: PhishPhage AI.
- [ ] Correct light/dark theme for the capture plan.

## Privacy and truthfulness

- [ ] No real personal email addresses or names.
- [ ] No private raw headers, tokens, secrets, or business information.
- [ ] No local absolute filesystem paths.
- [ ] No browser profiles, GitHub credentials, or unrelated applications.
- [ ] No active or live malicious URL.
- [ ] No stale result from a previous fixture.
- [ ] Actual health/readiness/model state is visible where relevant.
- [ ] Final 82/100 result is used only if reproduced by the synthetic regression input and labeled scenario-specific.

## Quality and accessibility

- [ ] High-resolution capture at the planned viewport.
- [ ] No browser console errors visible or present during review.
- [ ] Text is readable at 100% zoom and after README display.
- [ ] Accessibility review completed for heading hierarchy, focus state, and contrast.
- [ ] Risk state uses labels/icons/text in addition to color.
- [ ] Captions or transcript prepared for video.
- [ ] Images optimized without making evidence unreadable.
- [ ] Alt text added for every published screenshot or diagram.
- [ ] README placement reviewed and links point only to existing assets.

## Suggested alt text

| Asset | Alt text |
| --- | --- |
| `landing-light.png` | PhishPhage AI landing page showing explainable email analysis, three input modes, and an in-memory privacy boundary. |
| `dashboard-light.png` | PhishPhage AI dashboard showing sanitized synthetic scan summaries and security insights. |
| `analyzer-input.png` | Analyze Email workspace showing Quick Paste, raw source, and `.eml` input choices with privacy guidance. |
| `phishing-result.png` | Synthetic phishing analysis result showing a high-concern classification, evidence-backed score, and human-review recommendation. |
| `decision-safety.png` | Decision-safety panel showing rule and ML disagreement, preserved raw probability, and a bounded safety floor explanation. |
| `indicators.png` | Detailed synthetic email indicators grouped by identity, routing, authentication, action, and infrastructure. |
| `history.png` | Browser-local scan history showing sanitized synthetic records and clear/export controls. |
| `reports.png` | Reports workspace showing a privacy-safe report preview generated from sanitized synthetic scan history. |
| `settings.png` | Settings workspace showing local history preference, theme controls, and service status without secrets. |
| `api-swagger.png` | Local FastAPI Swagger page showing documented health and analysis endpoints without credentials. |
| `health-readiness.png` | Local PhishPhage AI health and readiness output showing actual service and model state without paths or secrets. |
| `architecture.svg` | PhishPhage AI architecture diagram connecting browser, FastAPI, parser, rules, approved ML, safety fusion, local history, registry, and observability. |
