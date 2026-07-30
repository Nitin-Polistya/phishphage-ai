# PhishPhage AI v1.0.0-rc1 release notes

Status: release-candidate preparation only. The tag `v1.0.0-rc1` has not been created, no release has been published, and no deployment has occurred.

## Release summary

This candidate packages the existing PhishPhage AI defensive email-analysis workflow with reconciled application metadata, validated model integrity, expanded documentation, and a release-gate record. It is intended for review, not production certification.

## Major capabilities

- Next.js frontend routes for landing, dashboard, analyzer, history, reports, and settings.
- FastAPI parsing and analysis routes for Quick Paste, raw RFC822, and `.eml` input.
- Deterministic evidence across content, identity, routing, authentication, URLs, and attachment metadata.
- Optional registry-selected calibrated Logistic Regression inference.
- Browser-local opt-in sanitized history and report generation.

## Decision-safety architecture

The system preserves raw ML probability, rule score, fusion inputs, evidence families, and presentation safety as separate fields. Asymmetric safety fusion can prevent an unjustified safe presentation or apply a bounded floor when independent evidence corroborates a high-concern message. The current synthetic impersonation fixture returned phishing/100 with raw ML probability 1.0 and applied the `brand_impersonation_with_routing_mismatch` floor.

## Security hardening

The release candidate retains bounded request/MIME parsing, exact CORS, request IDs, process-local rate limits, safe errors, CSP/security headers, no-store API responses, path-contained artifact loading, SHA-256 verification, privacy-safe logs, and CSV/report escaping. Attachment contents are not scanned; URLs are not fetched.

## Observability

Health, readiness, metrics, startup diagnostics, model load events, Firebase-disabled state, request completion events, and shutdown logging remain available. Logs do not include email content, credentials, raw addresses, URLs, model contents, or local paths.

## Deployment preparation

Docker, Render, Vercel, private model provisioning, HTTPS, CORS, readiness, and rollback guidance are documented. Auto-deploy remains disabled. Provider quotas, Docker execution, cloud capacity, private artifact release, and public deployment were not verified.

## Documentation and portfolio

README presentation, brand guidance, synthetic demo data, Mermaid diagrams, social-preview source, screenshot plan, demo walkthrough, recording plan, case study, interview guide, portfolio copy, accessibility guidance, and claim/privacy audits are included.

## Model qualification status

The registry selects `phase-c-logistic-regression-v1` version `1.0.0`, isotonic calibration, threshold `0.50`, registry `phase_d_registry_v1`, `deployment_candidate=true`, `activated=false`, and API compatibility `1`. The artifact, vectorizer, and feature-manifest hashes match locally. No experimental SVM or hybrid-feature candidate was promoted.

## Verification summary

- Backend: 245 passed, 2 known dependency deprecation warnings; compileall passed; pip check passed.
- Frontend: 33 Node tests passed; TypeScript passed; ESLint passed; Next.js 15.5.21 production build passed; npm audit found 0 vulnerabilities.
- Documentation: 86 relative links checked, 0 broken.
- Local startup: corrected `--app-dir apps/api` command reached health/readiness/metrics/docs successfully with model ready and fallback inactive; synthetic safe and phishing analysis requests returned HTTP 200.
- `npm ci`: timed out in sandboxed and escalated environments without output; this remains an environment limitation.

## Known limitations

- The root tracked `LICENSE` path is currently deleted locally while an untracked `LICENSE.md` exists; release licensing is unresolved.
- Browser automation remains blocked by host-level `spawn EPERM` in prior evidence; manual browser QA was not completed in this phase.
- The earlier 82/100 and 22.9% portfolio pair was not reproduced by the current fixture and must not be published as a current result.
- No API authentication/authorization, shared rate limiter, durable metrics backend, live reputation lookup, attachment-content scan, or cloud-capacity claim exists.

## Upgrade and rollback notes

Application metadata changes from `0.1.0` to `1.0.0-rc1`; model and API compatibility versions remain distinct and unchanged. Review the environment contract, provision the private model bundle, verify hashes, and pass readiness before any deployment. Roll back application/configuration and select a previously reviewed registry entry with matching private artifact hashes; see [ROLLBACK.md](ROLLBACK.md).
