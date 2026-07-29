# Changelog

All notable repository changes are documented here. The project has no historical release tags or released versions to summarize.

## [1.0.0-rc1] - 2026-07-29

This is a release candidate, not a final release. It has not been tagged, published, or deployed.

### Added

- Release-candidate validation reports, release notes, and a gated checklist.
- Synthetic portfolio fixtures, Mermaid diagrams, social-preview source, and privacy-reviewed presentation guidance.

### Changed

- Reconciled application and frontend package metadata to `1.0.0-rc1`.
- Reconciled the public API label to PhishShield AI while preserving internal compatibility/storage identifiers.
- Updated public API examples and environment guidance for the release-candidate version and JSON CORS origin lists.

### Fixed

- Removed stale `0.1.0` application examples from release-facing health/API metadata.
- Corrected portfolio documentation so the current synthetic fixture is reported as phishing/100 with raw ML probability 1.0; the unreproduced 82/100 and 22.9% pair is no longer treated as a current claim.

### Security

- Revalidated backend security/model-integrity coverage, artifact hashes, privacy-safe logging, and npm audit status.
- No model artifact, threshold, calibration, dataset, or registry activation state changed.

### Known limitations

- The root tracked `LICENSE` path is currently deleted locally while an untracked `LICENSE.md` exists; the license gate remains blocked until the user resolves that rename and confirms the license.
- `npm ci` timed out in both sandboxed and escalated environments; local frontend tests, type checking, lint, build, and audit passed using the available dependency tree.
- Browser automation, Docker/provider execution, cloud capacity, and public deployment remain unverified.
- The approved model remains a deployment candidate with `activated=false`.

## [Unreleased]

### Added

- Deterministic asymmetric safety fusion (`asymmetric-safety-v1`), bounded evidence-family floors, actionable `mailto:` parsing, tracking-pixel classification, explicit authentication semantics, severity-aware presentation, recommendation deduplication, and conservative legacy history/report migration.

- Complete documentation set for architecture, API, model governance, datasets, security, deployment, development, testing, and research.
- Contributor guidance, Code of Conduct, documentation reports, link/version/terminology audits, and license audit.
- Health, readiness, metrics, request IDs, privacy-safe structured logging, and deployment preparation evidence.
- Model artifact registry/hash-validation and inference-adapter documentation.

### Changed

- Standardized new public documentation on the canonical product name PhishShield AI while retaining internal PhishPhage identifiers where compatibility requires them.
- Documented optional browser-local history and its privacy boundary.
- Consolidated deployment, artifact distribution, rollback, CI/CD, observability, and security assumptions.
- Recorded the model adapter repair, rejected SVM qualification, hybrid feature outcomes, false-positive reduction work, and dataset limitations without promoting experimental candidates.

### Security

- Prevented stale, incomplete, unavailable, or unverified results from being presented or exported as safe/low risk; no approved model artifact, probability, threshold, calibration, dataset, or registry hash was changed.

- Documented request-size/MIME bounds, CORS, CSP, security headers, SSRF boundaries, safe errors, rate limiting, request IDs, logging privacy, artifact integrity, secret handling, Firebase status, and responsible disclosure.
- Recorded that interactive browser security verification remains inconclusive because the host blocks browser child processes.

### Performance and deployment

- Documented the existing synthetic performance baseline, process-local observability, Docker/provider manifests, private model provisioning, rollback plan, and unverified provider/tooling gates.

### Research outcomes

- Inference path repaired and API/direct artifact probabilities reconciled.
- Calibrated SVM and hybrid structured-feature experiments retained as research-only after false-positive/qualification gates failed.
- Current registry candidate remains unchanged and inactive.
