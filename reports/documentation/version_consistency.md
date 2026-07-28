# Version consistency audit

## Findings

| Surface | Observed value | Status |
| --- | --- | --- |
| Backend `APP_VERSION` default | `0.1.0` | Consistent with the frontend and ML package project version; it is an application label, not a release tag. |
| Frontend package version | `0.1.0` | Consistent with backend/ML package labels. |
| ML package version | `0.1.0` | Consistent as a package label. |
| Runtime registry model | `phase-c-logistic-regression-v1`, version `1.0.0` | Correctly distinct from the project package version; deployment candidate, inactive. |
| Registry version | `phase_d_registry_v1` | Registry metadata version, not a project release. |
| Experiment model metadata | `ml-english-template-robust-v3.0.0` | Historical/research identifier, not the registry record. |
| API pipeline freshness constant | `ml-english-template-robust-v3.0.0` | Inconsistent with the runtime registry adapter version `1.0.0`; can mark current registry results stale. |
| Frontend scan freshness constant | `ml-english-template-robust-v3.0.0` | Inconsistent with the runtime registry adapter version `1.0.0`. |
| API default name/description/root message | `PhishPhage AI API` | Product terminology inconsistency; not a numeric version issue. |
| Docker/provider manifests | No independent release version | No inconsistency found; they consume environment/registry values. |

## Decision

The numeric project labels were not changed because no verified release version exists and the package values are internally consistent. The runtime/research model-version mismatch was recorded rather than changed because correcting it would alter API freshness metadata and requires a separately reviewed compatibility decision. No threshold, calibration, inference behavior, or API contract was changed.
