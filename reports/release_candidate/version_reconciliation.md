# v1.0.0-rc1 version reconciliation

Audit date: 2026-07-29. The application release candidate is `1.0.0-rc1`; the Git tag is intentionally not created.

| Concept | Current value | Status / decision |
| --- | --- | --- |
| Application version | `1.0.0-rc1` | Reconciled in backend settings, API example, health example, and release docs. |
| Frontend package version | `1.0.0-rc1` | Reconciled in `apps/web/package.json` and the package-lock root metadata. |
| API compatibility | `/api/v1`, compatible API `1` | Unchanged; no unnecessary API rename. |
| Rule engine version | `rules-v3.1.0` | Runtime version; unchanged. |
| Model ID | `phase-c-logistic-regression-v1` | Registry-selected candidate; unchanged. |
| Model version | `1.0.0` | Distinct from application release; unchanged. |
| Calibration | `isotonic` | Unchanged. |
| Model threshold | `0.50` | Unchanged. |
| Registry version | `phase_d_registry_v1` | Distinct registry metadata version; unchanged. |
| Report schema | `1.3` | Frontend report schema; unchanged. |
| ML package version | `0.1.0` | Research/package label, not the application release; unchanged. |
| Dataset/research identifiers | Historical identifiers such as `ml-english-template-robust-v3.0.0` | Not runtime model identity; retained in historical research artifacts. |

The prior documentation version report described the pre-RC `0.1.0` state and is historical evidence. This report supersedes its application-version rows. The runtime API/frontend model freshness constants already match the registry model version `1.0.0`; no model-version, threshold, calibration, artifact, or registry edit was made.

The current public API label is now `PhishPhage AI API`; the project was renamed from `PhishShield AI`. Browser storage keys, research source IDs, and historical reports are compatibility/history data and were not renamed because doing so would change migration behavior or research provenance.
