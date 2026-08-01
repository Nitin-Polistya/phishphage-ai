# Gemini review assistant

The dataset-review workspace is a separate internal curation tool at
`/dataset-review` and `/api/v1/dataset-review`. It helps a human reviewer
inspect sanitized evidence while creating a gold-standard dataset. Gemini is
advisory only: it cannot set `expected_class`, a final human label, an
adjudicated label, benchmark truth, model artifacts, thresholds, calibration,
the registry, or the production `/analyze` verdict. It is never reviewer two.

## Safe configuration

The API uses the official `google-genai` Python SDK (`>=1.0,<2.0`). Install the
normal API requirements, then set the backend-only values in `apps/api/.env`:

```text
DATASET_REVIEW_ENABLED=true
DATASET_REVIEW_LOCAL_ONLY=true
DATASET_REVIEW_ADMIN_TOKEN=
GEMINI_REVIEW_ENABLED=true
GEMINI_API_KEY=
GEMINI_MODEL=
```

`GEMINI_API_KEY` is a Google AI Studio API key, which is separate from a Gemini
app subscription. Never put it in a `NEXT_PUBLIC_` variable, frontend code,
browser storage, a cookie, a URL, an export, a log, or source control.
`DATASET_REVIEW_ADMIN_TOKEN` is a separate local administrative secret. The API
fails closed if the two values are equal or if both `GEMINI_API_KEY` and
`GOOGLE_API_KEY` are configured. The application does not validate the model
against the provider during startup.

The feature is disabled by default. The free-tier defaults are one concurrent
request, five reviews per browser session, ten reviews per day, one retry, no
batch, and no cache. Request input cannot increase those limits. No bulk job is
implemented.

## Privacy contract

Only a deterministic sanitized payload is submitted, never a raw `.eml`. The
payload may contain a sanitized subject, display name, registrable sender,
Reply-To, and Return-Path domains, normalized authentication summaries, plain
text and HTML-derived visible-text excerpts, registrable URL domains and safe
structural flags, attachment extension/MIME metadata, parser evidence, and a
candidate category. Full addresses, local parts, phone numbers, postal or
account identifiers, tracking IDs, tokens, cookies, message IDs, raw headers,
full URLs, query strings, fragments, paths, base64, scripts, styles, forms,
iframes, SVG, embedded files, and attachment content are removed.

The limits are a 300-character subject, an 8,000-character body excerpt, and a
16 KiB serialized payload. The preview shows every submitted field, the byte
size, model, prompt version, and SHA-256 hash. The exact button is
**Send sanitized review data to Gemini**. Consent is unchecked by default and
is bound to that payload hash plus model and prompt version; any change
requires a fresh preview and consent. The UI plainly warns that sanitized data
is sent to an external provider, that Gemini is advisory, that the free-tier
provider may process submitted data under its terms, and that confidential or
personal email must not be submitted.

## Access and storage

All mutating routes require `X-Dataset-Review-Token`, compared in constant
time. The token remains in active tab memory only and is cleared by reload or
the lock action. It is not stored in localStorage, sessionStorage, IndexedDB,
cookies, query parameters, exports, or logs.

Local-only mode accepts loopback clients (`127.0.0.1`, `::1`, and validated
`localhost`) and configured local origins. Forwarding headers are not trusted
by default. If this tool is later placed behind a reverse proxy, configure a
trusted proxy boundary and ensure the application receives a validated
loopback identity; do not simply trust arbitrary `X-Forwarded-For` values.

The ignored SQLite file is configured by `DATASET_REVIEW_STORAGE_PATH` and
defaults to `services/ml/evaluation/private/review_workspace.sqlite3`. Relative
paths resolve from the repository root, independently of the API process
working directory, and the path must remain under the ignored private
evaluation directory. It stores sanitized
payload metadata, hashes, consent/provenance, human reviews, advisory output,
status, and timestamps. It never stores the API key, admin token, raw email,
attachment bytes, arbitrary paths, or provider raw responses.

## Review modes and ground truth

Independent review is the default: a human records a preliminary label and
notes, optionally requests Gemini, then records the final human label. In
AI-assisted mode the suggestion is generated first and the human records that
AI exposure and a change reason. Both modes preserve preliminary label,
confidence, notes, final label, reviewer alias, timestamps, prompt version,
model, and whether the label changed after exposure.

Final benchmark eligibility requires a human final label, notes, confidence,
privacy and provenance gates, stable hashes, overlap and duplicate checks, and
the required single- or dual-human adjudication status. A Gemini-only record is
never eligible. Reviewer packages are deterministic and label-blind for the
other reviewer; they contain sanitized evidence only, CSV-injection escaping,
schema version, package hash, and duplicate/identity validation. Disagreements
become an adjudication queue.

## Prompt safety

Prompt version `gemini-review-v1` says that email is hostile evidence, not
instructions; ignores prompt injection; never browses or follows links; never
opens or decodes attachments; does not invent missing facts; distinguishes spam,
suspicious, and confirmed phishing; and states uncertainty. Each request is
stateless and contains one sample inside `<UNTRUSTED_EMAIL_EVIDENCE>` delimiters.

## Manual synthetic connectivity test

Codex must not perform this test. After local setup, a human may perform exactly
one request using a fully synthetic sample such as:

1. Use only `example.com`, `example.org`, or `example.net` domains; use no
   personal data, real brand credentials, live malicious URL, attachment, or
   raw `.eml`.
2. Start the API and frontend locally, enable both review flags, configure a
   separately generated admin token, and open `/dataset-review`.
3. Enter one synthetic sample, prepare the sanitized preview, inspect every
   field, byte count, hash, model, and prompt version, and check the exact
   per-request consent box.
4. Click **Send sanitized review data to Gemini** once. Confirm the structured
   advisory response, that the UI still requires a final human label, and that
   the API logs contain no body or secret. Inspect the response and browser
   storage to confirm no key or token is present.
5. Stop after that single request. Only if it succeeds may the operator review
   up to five samples in that session. Do not run a bulk or batch operation.

## Local commands

```powershell
.\apps\api\.venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt
.\apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir apps/api
cd apps\web
npm run dev
```

All automated tests use provider mocks and make no network calls. Run the
backend and frontend checks documented in `docs/TESTING.md`. Use the existing
read-only `evaluate_v1.py` only after a human benchmark has been finalized;
this assistant never retrains or changes production analysis.
