# Model card and governance notes

## Status at a glance

The repository contains one runtime registry record:

| Field | Current registry value | Meaning |
| --- | --- | --- |
| Model ID | `phase-c-logistic-regression-v1` | Registry identifier selected by the API default. |
| Version | `1.0.0` | Registry/API-compatible artifact version. |
| Algorithm | Balanced Logistic Regression with calibrated probabilities | Text model used by the registry candidate. |
| Calibration | Isotonic | Stored calibration method; not a new calibration performed by this phase. |
| Threshold | `0.50` | Saved phishing decision threshold. It was not changed here. |
| Registry version | `phase_d_registry_v1` | Metadata registry version. |
| Deployment candidate | `true` | Candidate may be loaded when provisioned and verified. |
| Activated | `false` | The artifact is not activated or production-approved. |

There is therefore no currently activated or production-qualified model. “Approved artifact” in audit filenames means the registry-selected artifact under integrity controls; it must not be read as universal accuracy or production certification.

## Preprocessing and feature representation

The registry candidate uses subject and plain-text body text. Its feature configuration is a word TF-IDF plus chi-square selection schema:

- lowercase text;
- Unicode accent stripping;
- word n-grams `(1, 2)`;
- `min_df=1`, `max_df=0.95`;
- sublinear TF;
- up to 30,000 vectorizer features;
- 512 selected dimensions;
- balanced class weighting and random seed 42;
- Logistic Regression hyperparameter `C=1.0` in the deployment candidate metadata.

The runtime model sees normalized subject/body text through the verified predictor. It does not learn from the rule engine’s observational structured features. The API can expose structured feature diagnostics for explanation and research, but those diagnostics do not alter this fitted artifact.

## Calibration and threshold

The registry stores `calibration=isotonic` and `threshold=0.50`. The inference adapter reads the positive-class probability from the verified public `predict_proba` contract and classifies phishing when it is greater than or equal to the saved threshold. The API reports the threshold; it does not tune it per request. `ML_MARGINAL_ALERT_BAND` affects a narrowly gated fusion exception around the existing threshold; it does not change the model threshold.

## Artifact structure

The registry record refers to a reviewed candidate bundle containing:

- a fitted pipeline artifact;
- a vectorizer artifact;
- a feature manifest;
- model metadata and evaluation manifests in the development evidence;
- registry metadata with model ID, version, threshold, calibration, activation state, compatibility version, and hashes.

The candidate bundle is a local/private release input and is ignored by Git. A fresh environment must provision the pipeline, vectorizer, and feature manifest in the approved model directory. Raw training corpora and generated model binaries are not public repository assets.

## Registry behavior and artifact validation

`ModelManager` is the sole runtime selection authority. It:

1. reads the JSON registry and accepts only the supported schema/API version;
2. selects the configured deployment candidate;
3. resolves registry and override paths under the approved model directory;
4. checks that the pipeline, vectorizer, and feature manifest exist;
5. verifies each registry SHA-256 value before deserialization;
6. checks model ID, inactive metadata, label mapping, probability contract, and threshold;
7. caches the verified model per process without changing `activated` metadata.

Hash mismatch, path escape, missing files, invalid registry metadata, unsupported compatibility, invalid probability shape, NaN/Inf values, or an unexpected bundle fails closed. Joblib/Pickle deserialization remains an operator trust boundary; only reviewed artifacts may be provisioned.

## Inference adapter

The adapter requires a callable `predict_proba`, validates the class ordering `{legitimate: 0, phishing: 1}`, checks a finite `(1, 2)` probability array in `[0, 1]`, and returns legitimate/phishing probabilities in the documented order. The repaired inference path reconciled API probabilities with direct verified-artifact probabilities with zero absolute difference across the recorded audit sample. The repair corrected inference integration; it did not change the model, threshold, calibration, dataset, or API contract.

## Qualification status

The current model is a deployment candidate under registry integrity checks, not a production-approved model. Existing evidence is limited by source dominance, synthetic and templated benchmarks, incomplete provenance, and distribution shift. The external benchmark contains only 80 rows and was evaluated after model lock; it is not representative of inbox prevalence. The grouped/template-shift diagnostics show materially weaker behavior than fixed validation. No metric in this repository supports a claim of universal accuracy.

The independent candidate-qualification report is more decisive: the calibrated SVM candidate improved recall on the independent `spaphish_v5` source from `0.1094` to `0.2161`, but precision fell from `0.5298` to `0.4788` and FPR rose from `0.1069` to `0.2590`. It failed the predeclared precision and FPR gates, and its provenance was incomplete. It was rejected for activation.

## False-negative and false-positive considerations

False negatives are expected for unfamiliar wording, low lexical overlap, modern campaigns, multilingual messages, image-only lures, compromised legitimate accounts, and messages whose useful evidence is in headers/HTML/URLs rather than body text. The inference audit recorded that most samples in its challenge set remained below the fixed threshold; that is a diagnostic finding, not an inbox-rate estimate.

False positives are possible for ordinary password, invoice, account, support, collaboration, marketing, and security-notification language. Missing authentication is not automatically failure, but limited evidence can reduce confidence. Hard-negative and provider-specific coverage is too small and source-bound to establish a safe operating point.

## External validation findings

The locked Phase C evidence includes fixed validation, grouped diagnostics, template-shift diagnostics, an external 80-row benchmark, and a small hard-negative set. The reports show:

- fixed validation can look materially better than grouped/template-shift evidence;
- the external benchmark is useful as a locked diagnostic but small, synthetic/templated, and not a production prevalence sample;
- the current candidate’s template-shift recall is substantially below fixed-validation recall;
- a calibrated direct inference replay agrees with the repaired API path;
- observational feature extraction is present but not consumed by this text-only artifact.

See [reports/inference_audit/inference_integrity_report.md](../reports/inference_audit/inference_integrity_report.md), [reports/candidate_qualification/qualification_summary.md](../reports/candidate_qualification/qualification_summary.md), and [reports/candidate_qualification/final_qualification_recommendation.md](../reports/candidate_qualification/final_qualification_recommendation.md).

## Experimental candidates and rejected work

| Candidate/work | Status | Decision |
| --- | --- | --- |
| `phase-c-logistic-regression-v1` | Registry deployment candidate | Remains unchanged; not activated. |
| Calibrated LinearSVC/SVM candidate | Experimental candidate | Rejected for activation after independent precision/FPR gates failed. |
| Word/character/hybrid structured feature sets | Experimental candidates | Research-only; richer structured features increased false-positive risk or failed acceptance gates. |
| Organization/best-five/gated feature experiments | Experimental candidates | Gating did not meet the declared recall, precision, and hard-negative criteria. |
| Low-threshold and random-forest experiments | Experimental candidates | Diagnostic only; not an approved threshold or artifact. |

The SVM and hybrid experiments must not be presented as the production model. No experimental artifact is activated by the registry.

## Known limitations

- No live sender reputation, DNS, redirect, threat-intelligence, or mailbox-context lookup.
- No attachment-content inspection or execution.
- No guarantee for multilingual, image-only, novel, compromised-account, or template-shift phishing.
- Labels, campaign grouping, and provenance are uneven across datasets.
- Model probabilities are not guarantees of real-world likelihood.
- Runtime freshness metadata currently contains a separate research model-version constant; this is documented as a version inconsistency and requires reconciliation before release approval.

## Retraining policy

Retraining is a separate governed activity. It requires licensed and privacy-reviewed data, documented label provenance, exact/normalized/semantic deduplication, campaign/template grouping, isolated validation and external evaluation, calibration review, explicit false-positive/false-negative gates, model and manifest hashes, adapter tests, and a release decision. Training scripts and data-acquisition audits are not a license to retrain during documentation work.

## Model governance

Every candidate should be classified as one of:

- experimental candidate: research output, never selected for runtime by default;
- deployment candidate: registry metadata allows loading but `activated` may remain false;
- activated model: explicit release decision and registry state, not present in the current repository;
- rejected candidate: failed a declared gate or provenance review and must not be promoted.

Changes to model ID, version, calibration, threshold, feature manifest, or activation require a separately reviewed change with reproducible evidence and rollback metadata. A documentation update cannot promote a candidate.

## Safe-use disclaimer

Use the model as one input to human review. Independently verify requests for credentials, payments, downloads, or account changes through an official channel. A “safe” result can reflect incomplete evidence and does not guarantee that the message is safe.
