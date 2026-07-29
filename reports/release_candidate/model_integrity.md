# Model and registry integrity gate

Status: **Pass for the available local candidate; candidate remains inactive.**

| Check | Result |
| --- | --- |
| Model ID | `phase-c-logistic-regression-v1` |
| Model version | `1.0.0` |
| Registry version | `phase_d_registry_v1` |
| Calibration | `isotonic` |
| Threshold | `0.50` |
| Deployment candidate | `true` |
| Activated | `false` |
| Compatible API | `1` |
| Artifact presence | Present locally and ignored by Git |
| Pipeline SHA-256 | Matches registry `d25bbc...d362` |
| Vectorizer SHA-256 | Matches registry `8d1e6c...c01` |
| Feature manifest SHA-256 | Matches registry `8744e7...d99c` |
| Adapter/inference tests | Included in 245-test backend pass |
| Startup load/warm-up | Passed with `ML_REQUIRED=true`; fallback inactive |
| Direct/API reconciliation | Existing integrity audit records zero absolute difference; no artifact change made |

The local startup emitted `model.registry_loaded`, `model.artifact_verified`, `model.loaded`, and `model.warmup_complete` events. Health reported `model_available=true`, `inference_ready=true`, `hash_verified=true`, and registry status `ready`. No experimental candidate was activated.

Direct synthetic pipeline checks returned:

- `safe_business_email.eml`: safe, score 0, safety `eligible`, safe verdict allowed.
- `phishing_brand_impersonation.eml`: phishing, score 100, safety `needs_review`, safety floor `brand_impersonation_with_routing_mismatch`, raw ML probability `1.0`.
