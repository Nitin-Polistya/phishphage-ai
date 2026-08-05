# College screenshot plan

All screenshots are manual deliverables. Use only synthetic inputs and review
each capture for private history, tokens, API keys, email addresses, raw
message bodies, full URLs, and local private paths before sharing. The plan does
not claim that any listed image has been captured.

Recommended primary viewport: **1440×900**. Use **390×844** only when a mobile
layout is useful. Prefer PNG with the filename shown below.

| # | Capture | Recommended filename | Viewport | Status / notes |
|---:|---|---|---|---|
| 1 | Landing page | `college-01-landing.png` | 1440×900 | Manual capture required |
| 2 | Dashboard | `college-02-dashboard.png` | 1440×900 | Manual capture required |
| 3 | Analyzer input modes | `college-03-analyzer-input.png` | 1440×900 | Show Quick Paste/raw/.eml options |
| 4 | Safe result | `college-04-safe-result.png` | 1440×900 | Use `safe_business_email.eml` |
| 5 | Phishing result | `college-05-phishing-result.png` | 1440×900 | Use synthetic brand-impersonation fixture |
| 6 | Explainability section | `college-06-explainability.png` | 1440×900 | Show signals and recommendations |
| 7 | History | `college-07-history.png` | 1440×900 | Sanitized records only |
| 8 | Reports | `college-08-reports.png` | 1440×900 | No raw body or private URL |
| 9 | Settings | `college-09-settings.png` | 1440×900 | Hide environment values |
| 10 | Dataset Review | `college-10-dataset-review.png` | 1440×900 | Local feature state only |
| 11 | Bulk Review | `college-11-bulk-review.png` | 1440×900 | Synthetic queue or approved empty state |
| 12 | Gold-dataset metrics | `college-12-gold-metrics.png` | 1440×900 | Capture only if locally configured |
| 13 | Export result | `college-13-export-result.png` | 1440×900 | Show filenames/counts, not private paths |
| 14 | Swagger/API docs | `college-14-swagger.png` | 1440×900 | Use local `/docs`; hide request secrets |
| 15 | Architecture diagram | `college-15-architecture.png` | 1440×900 | Render `ARCHITECTURE.md` Mermaid manually |
| 16 | Test result terminal | `college-16-test-results.png` | 1440×900 | Show commands/output only |
| 17 | Model health status | `college-17-model-health.png` | 1440×900 | Show actual inactive/unavailable state |

## Capture procedure

1. Start the local API and frontend using [COLLEGE_DEMO_GUIDE.md](COLLEGE_DEMO_GUIDE.md).
2. Confirm the health/readiness state before capturing.
3. Load only synthetic fixtures from [`assets/demo/`](assets/demo/).
4. Capture the smallest useful viewport region without browser profile data.
5. Check the image at 100% zoom for private or secret content.
6. Use a descriptive filename and store the final approved image in the
   college submission location, not in private review storage.
7. Record the actual date, viewport, API/model status, and fixture name in the
   presentation notes.

## Existing image caution

The repository contains earlier design and validation images at the repository
root. They are not automatically college evidence. A human must confirm their
source, displayed data, model state, and privacy before reusing them.
