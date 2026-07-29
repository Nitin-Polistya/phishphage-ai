# v1.0.0-rc1 release checklist

Unchecked mandatory items block tagging.

## Repository and release identity

- [x] Baseline branch and remote recorded.
- [ ] Working tree clean after the release commit.
- [x] Feature freeze declared; only release metadata, correctness, documentation, and validation changes made.
- [ ] Commit pushed after user approval.
- [ ] User-approved root license selected and tracked as `LICENSE`.
- [ ] Tag `v1.0.0-rc1` created only after all gates pass.

## Validation

- [x] Backend pytest: 245 passed, 2 known deprecation warnings.
- [x] Backend compileall.
- [x] Backend pip check.
- [x] Frontend Node tests: 33 passed.
- [x] Frontend TypeScript.
- [x] Frontend ESLint.
- [x] Frontend production build.
- [x] npm audit: 0 vulnerabilities.
- [ ] `npm ci` completes in a clean environment; current sandboxed and escalated attempts timed out.
- [x] Model hashes verified and registry state unchanged.
- [x] Backend starts with model ready and fallback inactive when launched with `--app-dir apps/api` and JSON CORS origins.
- [ ] Fresh frontend `npm start` verification after a clean install; an existing local port-3000 process returned HTTP 200 for all six routes, but its startup log predates the RC metadata change.
- [x] Health, readiness, metrics, and Swagger endpoints respond successfully.
- [x] Synthetic safe scan succeeds and is safe-eligible.
- [x] Synthetic phishing scan succeeds and applies decision safety.
- [ ] Manual browser QA completed.
- [x] Documentation links pass.
- [x] Security gate has no known Critical/High vulnerability; browser/pip-audit limitations documented.
- [x] Performance baseline reviewed with accepted tooling limitations.
- [x] Observability startup/request/model events reviewed.

## Release artifacts

- [x] Deployment documentation reviewed; no deployment performed.
- [x] Release notes added.
- [x] Changelog updated without marking the release final.
- [x] Portfolio assets and claims reviewed; missing screenshots/video remain manual deliverables.
- [x] Rollback reference included.
- [ ] GitHub release draft created after commit/tag approval.

## Outcome

Current outcome: **D — blocked by unresolved license state.** Additional clean-install and manual/browser tooling limitations must also be resolved or explicitly accepted before tagging. Do not tag until the license is resolved and the user approves the release commit/tag workflow.
