# Testing guide

Testing uses synthetic input and sanitized fixtures. Do not add real personal email, credentials, live malicious URLs, or attachment bytes to tests or reports.

## Backend unit and integration tests

The API suite covers parser behavior, MIME/attachment metadata, input modes, rules, URL/domain analysis, analysis completeness, fusion, inference adapter behavior, model registry/hash alignment, deployment configuration, security middleware, observability, performance baselines, and research-report schemas.

Run the requested backend suite:

```powershell
.\apps\api\.venv\Scripts\python.exe -m pytest -q apps/api/tests
```

The repository also contains service/ML tests where available:

```powershell
.\apps\api\.venv\Scripts\python.exe -m pytest -q apps/api/tests services/ml/tests
```

Expected output is a zero exit code and a passing test summary. Exact counts vary with pytest/plugin versions and local fixture availability.

## Security tests

Backend security tests exercise request-size and parser bounds, rate limits, request IDs, CORS restrictions, headers/CSP, safe error behavior, path containment, and model-integrity failures. Frontend security tooling under `apps/web/tests/security/` checks routes, local-storage behavior, report serialization, and synthetic browser flows when a browser can launch.

The recorded security audit did not complete interactive browser verification: the host rejected the Playwright worker and Chromium child process with `spawn EPERM`/access denied. No browser pass is claimed.

## Frontend tests

The normal frontend script runs Node tests for UI transformations, attachment metadata, inference UI, production-analysis UI, local reports, and scan-store behavior:

```powershell
cd apps\web
npm test
npx --no-install tsc --noEmit
npm run lint
npm run build
npm audit
cd ..\..
```

`tsc` verifies the checked-in TypeScript program; ESLint checks source rules; `next build` verifies a production build. `npm audit` is a dependency advisory check and may report findings even when application tests pass.

## Deployment tests

Deployment tests cover environment validation, CORS/proxy assumptions, the Docker/provider configuration shape, artifact provisioning with mocked network responses, readiness semantics, rollback assumptions, and no-overwrite/hash behavior. They do not deploy, contact a cloud provider, download a real private artifact, or prove provider quotas/capacity.

The Dockerfile can be inspected statically when Docker is unavailable. A real release gate must build the image in a clean environment and run startup with a private reviewed artifact.

## Observability tests

Observability tests cover request completion logging fields, request-ID propagation, privacy-safe client identity, health/readiness/metrics shape, startup state, process-local counters, and error behavior. Counters are expected to reset between process starts.

## Performance tooling tests

Performance scripts and tests cover synthetic payload scaling, MIME/parser timing, warm inference, bounded concurrency, rate-limit behavior, and report generation. Browser Web Vitals, host-level RSS/CPU profiling, provider capacity, and production-class cold-start measurements are not available in the current environment.

## Model adapter and evaluation scripts

Model tests cover the verified registry path, hash checks, threshold/metadata alignment, class ordering, probability shape, finite values, fallback status, and direct/API reconciliation. Evaluation scripts under `services/ml/scripts` include corpus audits, language/deduplication checks, model evaluation, fixture evaluation, inference verification, candidate qualification, hybrid feature experiments, and source-boundary audits.

Research/evaluation commands must use the documented data boundary and review gate. They are excluded from normal tests when they require ignored datasets, private artifacts, network access, or explicit approval. No evaluation command in this documentation phase retrains or promotes a model.

The gold-standard curation tests in `apps/api/tests/test_gold_standard_dataset.py`
use synthetic fixtures only. They cover schema and label vocabulary validation,
duplicate IDs, missing campaign/date handling, privacy redaction, stable hashes,
exact overlap detection, provisional versus adjudicated state, final
eligibility, deterministic ordering, public-manifest safety, label-blind
ingestion, empty-benchmark behavior, and minimum-size warnings.

## Synthetic data policy

Use `example.com`, fabricated names, fabricated IDs, and non-routable or clearly synthetic content. Tests may assert URL parsing and security behavior without opening destinations. Fixtures under the repository are sanitized and must not be expanded with copied mailbox content. Reports should use aggregates, hashes, or redacted examples.

## Privacy requirements

Tests must not persist raw input in logs, snapshots, local storage assertions, test output, generated reports, screenshots, or failure traces. Verify that report serializers exclude raw bodies and complete raw headers. Clear local browser state before browser security tests.

## Useful validation commands

```powershell
.\apps\api\.venv\Scripts\python.exe -m compileall apps/api/app apps/api/scripts services/ml/src
.\apps\api\.venv\Scripts\python.exe -m pip check
git diff --check
```

## What is excluded from normal tests

### Decision-safety regression matrix

Synthetic tests cover the preserved score formula; high-confidence multi-family floors; duplicate-family suppression; moderate floors; weak-rule/high-ML disagreement; aligned-domain/authentication protection; `mailto:` parsing, decoding, malformed input, action classification, and privacy-safe export; tracking-pixel versus actionable URL classification; explicit authentication states; UI severity labels; recommendation deduplication and caps; report/history migration; and raw/pre-floor/post-floor preservation. The observed Microsoft-style disagreement fixture is verified to remain phishing/high concern after the rule floor while retaining its lower ML probability.

- Public/cloud deployment and automatic commits.
- Real artifact downloads and private provider URLs.
- Raw dataset acquisition, training, threshold changes, and model activation.
- Interactive browser checks when host process policy blocks browser launch.
- Live URL/DNS reputation and attachment execution.
- Claims about production accuracy, universal detection, or certification.

## Dataset-review validation

Gemini tests use a fake `google-genai` client and never access the network. They
cover disabled flags, local-only access, token authorization, sanitization and
limits, hash-bound consent, strict structured output, provider failures,
human-only labels, deterministic reviewer packages, and session/daily limits.
Do not configure a live provider request in automated tests.
