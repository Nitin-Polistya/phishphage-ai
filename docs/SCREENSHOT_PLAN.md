# Portfolio screenshot plan

All captures use synthetic input from [`assets/demo/`](assets/demo/) or the app's built-in example. Do not capture real inboxes, provider dashboards, private artifact paths, or raw backend errors. If the model is unavailable, show the actual degraded/offline state and label the capture accordingly.

## Capture matrix

| # | Screenshot | Route | Viewport / theme | Test data | Must be visible | Must be hidden | Filename | README placement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Landing page | `/` | 1440x900, light | No email data | PhishShield AI name, tagline, input modes, privacy boundary, primary CTA | Browser tabs, local paths, fabricated metrics | `landing-light.png` | Hero gallery, first image after the introduction |
| 2 | Dashboard | `/dashboard` | 1440x900, light | Synthetic scan summaries only | Overview cards, recent scans, safety/privacy language | Real history, personal names, stale backend errors | `dashboard-light.png` | Capabilities gallery |
| 3 | Analyzer input modes | `/analyze` | 1440x900, light | Quick Paste fields plus synthetic raw/EML options | Quick Paste, Raw Email, `.eml Upload`, limits, privacy notice | Real mailbox content, secrets, active destinations | `analyzer-input.png` | Demo flow |
| 4 | High-risk phishing result | `/analyze` after `phishing_brand_impersonation.eml` | 1440x900, light | Synthetic Microsoft-style fixture | Final classification, score, raw ML probability, result freshness | Any edited number, live link, raw full headers | `phishing-result.png` | Results gallery |
| 5 | Decision-safety panel | `/analyze` result details | 1440x900, dark | Same synthetic impersonation fixture | Rule/ML disagreement, pre-floor and post-floor explanation, review recommendation | Claims of universal accuracy or automated blocking | `decision-safety.png` | Results gallery |
| 6 | Detailed indicators | `/analyze` result details | 1440x900, light | Same fixture | Identity, routing, authentication, action, and infrastructure evidence | Full email body, private headers, clickable destinations | `indicators.png` | Results gallery |
| 7 | Scan history | `/history` | 1440x900, light | Sanitized synthetic records created locally | Local-only label, verdicts, timestamps, clear/export affordances | Personal history, raw message content, browser profile data | `history.png` | Privacy section |
| 8 | Reports | `/reports` | 1440x900, light | One or more synthetic sanitized records | Report preview, redaction boundary, export action | Raw bodies, complete headers, private identifiers | `reports.png` | Privacy section |
| 9 | Settings | `/settings` | 1440x900, dark | Default local preferences | History preference, theme, API status, version labels | Secrets, populated private environment variables | `settings.png` | Privacy/security section |
| 10 | API Swagger | `/docs` on local FastAPI | 1440x900, light | No request body required | Route groups and safe endpoint descriptions | Authorization tokens, real payloads, local absolute paths | `api-swagger.png` | Technical appendix |
| 11 | Health/readiness output | `/api/v1/health`, `/ready` | 1280x720, light | Local service with actual model state | `status`, service, model availability, startup/readiness state, no secrets | Artifact filesystem paths, raw logs, credentials | `health-readiness.png` | Technical appendix |
| 12 | Architecture diagram | Rendered Mermaid source | 1600x900, light | No email data | Browser, FastAPI, parser, rules, ML, safety, local history, optional Firebase, registry, provisioning, observability | Unlabeled arrows, private artifact URLs, deployment claim | `architecture.svg` | Architecture section |

## Capture rules

- Use a clean browser profile at the stated viewport and capture at device scale factor 1 or higher.
- Keep the displayed backend/model/readiness status truthful; never replace `unavailable` with `connected` in an image editor.
- Avoid horizontal cropping of evidence cards and preserve text at readable size.
- Add the recommended alt text in [`PORTFOLIO_ASSET_CHECKLIST.md`](PORTFOLIO_ASSET_CHECKLIST.md) or the README gallery when a file is added.
- The README should contain image links only after the corresponding reviewed file exists. Until then, use the filename placeholder table in the README.
