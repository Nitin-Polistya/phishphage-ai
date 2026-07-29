# Research and experimentation history

This is a compact account of the repository's documented development and audit phases. Research artifacts are evidence, not runtime approvals. No experiment in this phase changed the active threshold, calibration, dataset, inference contract, frontend behavior, or deployment state.

## Phase table

| Phase | Objective | Result | Decision |
| --- | --- | --- | --- |
| Baseline model development | Establish a calibrated text classifier and fixed threshold | Word TF-IDF Logistic Regression was retained as the precision-control baseline; the saved threshold is 0.50. | Keep the baseline under registry governance. |
| Feature coverage audit | Compare observed phishing signals with learned model inputs | The API exposes structured observational features, but the approved fitted pipeline remains text-only. | Report coverage; do not imply those features affect inference. |
| Inference integrity audit | Reconcile API output with direct artifact replay | The inference path was repaired. Artifact, schema, calibrator, threshold, finite-vector, and fallback checks passed; API and direct artifact probabilities reconciled. | Keep the repaired adapter and unchanged model configuration. |
| Controlled model experiments | Compare Logistic Regression, SVM, random forest, calibration, and thresholds | Some candidates improved recall on internal/grouped diagnostics, but apparent gains were sensitive to data boundary and false positives. | Research-only; no candidate promotion. |
| Independent candidate qualification | Test a calibrated SVM candidate on independent `spaphish_v5` evidence | Recall improved from 0.1094 to 0.2161, while precision fell from 0.5298 to 0.4788 and FPR rose from 0.1069 to 0.2590. Predeclared precision/FPR gates failed; provenance was incomplete. | Reject SVM candidate for activation. |
| Hybrid feature experiments | Add structured/authentication/organization/URL/urgency features | Organization and best-five groups improved recall in selected diagnostics but exceeded false-positive/hard-negative budgets; gating did not meet acceptance criteria. | Do not enter engineered feature groups into production. |
| False-positive reduction work | Reduce legitimate-provider and missing-authentication regressions | Evidence-correlation and marginal-alert handling improved targeted fixture behavior without moving the saved ML threshold. | Keep the narrow rule/fusion repair; do not claim inbox-wide FP performance. |
| Dataset evolution | Audit provenance, duplicates, campaigns, languages, and coverage gaps | Source dominance, synthetic/template concentration, incomplete provenance, and modern campaign gaps remain major constraints. | Prioritize licensed, privacy-reviewed, campaign-grouped hard negatives and modern phishing coverage. |

## Inference integrity defect and repair

The audit found an inference integration defect: the API path did not previously reconcile with the calibrated artifact probability. The repaired path now uses the verified model adapter and direct `predict_proba` output. The recorded reconciliation shows zero absolute difference for the audited samples, no fallback use, a stable 512-feature shape, finite values, registry model/version agreement, and threshold match at 0.50.

The repair did not make the model more accurate. It made the API represent the existing artifact correctly. Observational feature coverage remains explicitly diagnostic because the saved pipeline does not consume that feature layer.

## Controlled model experiments

The experiments compared text-only and richer representations under fixed seeds and declared boundaries. Internal grouped/template-shift behavior was materially weaker than fixed validation, showing source/template shift. Low thresholds and higher-recall classifiers increased false-positive risk. Results from a research artifact, a diagnostic challenge set, or a small external benchmark are not production prevalence estimates.

## Independent candidate qualification

The independent qualification report records the calibrated LinearSVC/SVM candidate as rejected. Although recall improved on `spaphish_v5`, FPR exceeded the declared maximum and precision fell below the declared minimum. Campaign/language provenance and semantic near-duplicate status were also unavailable. The final recommendation explicitly says the candidate must not be activated or deployed.

## Hybrid feature experiments

Structured feature families included authentication, organization/provider language, financial, credential, urgency, infrastructure, and combinations such as best-five/all. The independent results show organization and best-five gains accompanied by FPR increases; gated variants did not satisfy the declared recall/precision/hard-negative gates. The hybrid recommendation is therefore research-only. A future text-plus-structured retraining cycle would require provider-aware semantics and provenance-complete validation.

## False-positive reduction

The rules/fusion work treats authentication evidence as pass, fail, inconclusive, or missing; missing evidence is not failure. It correlates sender/link alignment and prevents authentication context from suppressing stronger malicious evidence. A narrow marginal alert exception can qualify a low-severity, aligned, missing-authentication case without changing the model threshold. The targeted legitimate regression set moved from one suspicious result to five safe results in the documented sanitized fixtures, but this is not a general inbox false-positive rate.

## Dataset evolution

The current audit reports 298 development-pool rows, 271 campaign groups, and a dominant Zenodo source. Modern SaaS/OAuth/MFA/collaboration/cloud-storage/QR/crypto/AI campaign coverage and matched legitimate workflows remain limited. Proposed additions require source licensing, privacy review, deduplication, independent campaign grouping, language review, and external holdout isolation. No dataset acquisition or retraining occurred here.

## Conclusions

- The inference path was repaired.
- API probabilities and direct artifact probabilities reconciled.
- The SVM improved recall but failed false-positive/precision gates.
- Hybrid structured features improved recall in selected diagnostics but increased FPR and failed gating.
- Gating did not meet acceptance criteria.
- Dataset quality and diversity remain major limitations.
- The current registry production candidate remains unchanged, remains inactive, and is not described as universally accurate or production-certified.

## Evidence index

### Decision-safety research boundary

Phase I.4D is a deterministic safety-fusion and explainability change, not a model experiment. It records the preserved pre-floor arithmetic, policy version, independent evidence families, applied floors, protective evidence, actionable `mailto:` destinations, tracking-pixel classification, and explicit authentication states. It does not retrain, recalibrate, alter the 0.50 decision threshold, change datasets, change model artifacts or hashes, or promote an experimental artifact.

- [Inference integrity report](../reports/inference_audit/inference_integrity_report.md)
- [Candidate qualification](../reports/candidate_qualification/final_qualification_recommendation.md)
- [Hybrid feature recommendation](../reports/hybrid_features/recommendation.md)
- [Dataset evolution summary](../reports/dataset_evolution/executive_summary.md)
- [Model card](MODEL.md)
