# Changelog

All notable repository changes are documented here. The project has no historical release tags or released versions to summarize.

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
