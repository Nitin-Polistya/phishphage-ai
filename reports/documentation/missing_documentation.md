# Missing documentation and accepted gaps

## Required documents

No required Phase I.5 document remains absent after this pass. Public guides are under `docs/`, community/policy files are at the repository root, and generated audit output is under `reports/documentation/`.

## Accepted repository gaps

- No root `LICENSE` file exists. This is a legal/project decision, not a documentation omission; see [license_audit.md](license_audit.md).
- Screenshot image files under `docs/images/` are intentionally not fabricated or committed.
- Interactive browser security verification is unavailable because the host rejects browser child processes with `spawn EPERM`/access denied.
- Docker execution, provider-like startup, provider capacity, cloud quotas/pricing, private artifact release, and deployed HTTPS smoke tests remain unverified.
- The API and frontend use a research model-version constant for freshness checks while the registry-selected runtime artifact reports `1.0.0`; see [version_consistency.md](version_consistency.md).

These gaps are explicitly documented rather than hidden. No model, dataset, threshold, calibration, inference path, API contract, frontend behavior, security control, or deployment was changed to mask them.

## Structure cleanup recommendation

No unrelated generated reports were deleted. Package-specific `apps/api/README.md` and `services/ml/README.md` remain useful local/package references but contain historical naming and research detail; keep them for now and cross-check them against the canonical public guides during future code changes. Generated research/security/performance/deployment outputs remain under `reports/` as requested. No internal focus-chain files are referenced by the new public documentation.
