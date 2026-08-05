# Offline demo backup

This fallback keeps the presentation honest when the API, browser, Wi-Fi, or
optional Gemini path is unavailable. It is a presentation plan, not an
automated video-generation instruction.

## Record a 2–3 minute backup

1. Use the local demo guide to start the backend and frontend.
2. Clear personal history and close secret-bearing terminals.
3. Capture the landing page, architecture, analyzer input, safe result, phishing
   result, explainability, model status, and API health.
4. Record a short narration following the sequence below.
5. Review the recording frame-by-frame for raw email, addresses, tokens, keys,
   private paths, and full private-dataset URLs.
6. Save the approved recording outside the repository unless it is explicitly
   part of the college submission package.

## Keep these screenshots

- `college-01-landing.png`
- `college-03-analyzer-input.png`
- `college-04-safe-result.png`
- `college-05-phishing-result.png`
- `college-06-explainability.png`
- `college-12-gold-metrics.png` when available
- `college-14-swagger.png`
- `college-15-architecture.png`
- `college-16-test-results.png`
- `college-17-model-health.png`

The complete list and privacy review steps are in
[COLLEGE_SCREENSHOT_PLAN.md](COLLEGE_SCREENSHOT_PLAN.md).

## Two-minute narration

1. “PhishPhage AI is an academic prototype for explainable phishing triage.”
2. “It parses email locally, runs deterministic indicators, and optionally
   consults a registry-controlled text model.”
3. “The safe fixture shows a low-risk routine note; that result is not a safety
   guarantee.”
4. “The phishing-style fixture shows urgency, account action, routing, and
   authentication evidence.”
5. “The result keeps probability, signals, and recommendations visible so a
   reviewer can challenge the conclusion.”
6. “The current approved-gold result has precision 0.9630 but recall 0.5200,
   with 24 false negatives among 50 phishing records.”
7. “The model remains inactive, Gemini is advisory-only, and future improvement
   requires more independent human-reviewed data.”

## If Wi-Fi fails

- Use the approved local recording and screenshots.
- Explain that core parsing, rules, and the planned demo are local.
- Do not imply that an external service was contacted.
- Continue with the architecture, report, metrics, and limitation discussion.

## If Gemini fails

- Continue with the normal analyzer demonstration.
- Show the human-only Dataset Review workflow if configured.
- State that Gemini is optional and advisory-only.
- Do not substitute a fabricated recommendation or label.

## If the backend does not start

- Stop trying to repair the environment during the presentation.
- Use the health, model-status, and analysis screenshots/recording.
- Explain the expected API boundary and startup command from the demo guide.
- Describe any unavailable state accurately.
- Do not claim that a live request succeeded.

## If the frontend does not start

- Use the architecture diagram, API Swagger screenshot, and result screenshots.
- Walk through the request/result sequence verbally.
- Explain that the UI is a client of the typed FastAPI contract.

## Privacy rules for the fallback

- Use reserved `.example` domains and fabricated names only.
- Never display `.env`, access tokens, private SQLite records, or raw datasets.
- Do not copy the recording into a public issue, repository, or chat without
  reviewing every frame.
- Keep the distinction between verified local facts, supplied approved-gold
  metrics, and future work clear.
