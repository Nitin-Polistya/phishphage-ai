# College local demo guide

This guide is for a local academic demonstration. Use only the synthetic
fixtures in [`docs/assets/demo/`](assets/demo/). Do not paste private email,
credentials, real organizations, or live malicious URLs. Do not depend on
Gemini during the live demo.

## Start the backend

Open a PowerShell terminal:

```powershell
cd D:\Development\Projects\phishphage-ai\apps\api
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If the virtual environment is already configured, the equivalent repository-root
command is:

```powershell
.\apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Start the frontend

Open a second PowerShell terminal:

```powershell
cd D:\Development\Projects\phishphage-ai\apps\web
npm run dev -- -p 3000
```

If port `3000` is busy, use:

```powershell
npm run dev -- -p 3001
```

The frontend must use the matching local API base URL from
`apps/web/.env.local`. Do not open or display `.env` files during the demo.

## URLs

Use `http://127.0.0.1:3000` below, or replace `3000` with `3001` when the
fallback port is required.

| Screen | URL |
|---|---|
| Frontend landing page | `http://127.0.0.1:3000/` |
| Analyzer | `http://127.0.0.1:3000/analyze` |
| Dashboard | `http://127.0.0.1:3000/dashboard` |
| History | `http://127.0.0.1:3000/history` |
| Reports | `http://127.0.0.1:3000/reports` |
| Dataset Review | `http://127.0.0.1:3000/dataset-review` |
| Settings | `http://127.0.0.1:3000/settings` |
| API documentation | `http://127.0.0.1:8000/docs` |
| API health | `http://127.0.0.1:8000/health` |
| API readiness | `http://127.0.0.1:8000/ready` |

## Synthetic examples

- Safe: [`safe_business_email.eml`](assets/demo/safe_business_email.eml)
- Phishing-style: [`phishing_brand_impersonation.eml`](assets/demo/phishing_brand_impersonation.eml)
- Optional suspicious comparison: [`suspicious_account_alert.eml`](assets/demo/suspicious_account_alert.eml)

The safe example is a routine synthetic internal note using reserved example
addresses and an explicit synthetic authentication pass. The phishing-style
example contains urgency, account verification, routing mismatch, failed
authentication, and an inert reserved-domain destination. The examples are not
benchmarks and must not be opened in a browser as links.

## Recommended demonstration sequence

1. Open the landing page and state that this is an academic/research prototype.
2. Explain the architecture diagram and the local privacy boundary.
3. Open the analyzer and show backend/model status.
4. Analyze the known-safe synthetic email.
5. Explain the low-risk result, visible evidence, and the fact that low risk is
   not a guarantee.
6. Analyze the synthetic phishing-style email.
7. Explain the score, probability, signals, authentication/routing evidence,
   and recommended independent verification.
8. Show history, using only sanitized browser-local records if enabled.
9. Show reports and explain that browser reports are local summaries.
10. Open Dataset Review briefly and explain human authority, sanitization, and
    optional advisory Gemini behavior.
11. Show the gold-dataset metrics/dashboard only if the local review session is
    configured; do not invent empty or unavailable values.
12. Open Swagger/API docs and show the health endpoint.
13. Close with the approved-gold metrics and limitations: precision 0.9630,
    recall 0.5200, 24 false negatives, inactive registry candidate.

## What to say about Gemini

“Gemini is optional and advisory-only. It receives sanitized review evidence
only when the local review feature is explicitly enabled. A human reviewer
must record the final label; Gemini cannot change production inference, gold
labels, the threshold, or registry activation.”

If Gemini is unavailable, continue the demo. The analysis path and human-only
review explanation do not depend on it.

## What to say about the model

“The current registry candidate is `phase-c-logistic-regression-v1`, version
`1.0.0`, with threshold 0.50. It is inactive. The approved-gold evaluation has
high precision but recall of 0.5200, with 24 false negatives among 50 phishing
records. The project therefore supports human triage and does not claim
production readiness.”

## Reset and privacy check

Before recording or presenting:

- clear any personal browser history;
- use only the two synthetic fixtures;
- close `.env` and terminals containing secrets;
- verify no private review records are visible;
- confirm the current backend/model status is shown as it actually is;
- keep URLs as inert text and never follow them.
