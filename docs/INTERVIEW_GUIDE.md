# PhishPhage AI interview guide

Answers are intentionally candid about the current scope and failed experiments.

## Why Logistic Regression?

The approved candidate is a text-oriented Logistic Regression pipeline because it is fast, inspectable, straightforward to calibrate, and easier to govern than a more opaque model for this project. The choice is a precision-control baseline, not a claim that it is the best classifier for every phishing family.

## Why not promote the SVM?

The calibrated SVM improved recall in an independent diagnostic, but precision fell and false-positive rate rose beyond the declared gates. Provenance and campaign/language status were also incomplete. It remained a research artifact and was rejected for activation.

## Why use rules and ML together?

Rules provide deterministic, inspectable evidence for identity, routing, authentication, action, URLs, and attachment metadata. ML can generalize across text patterns but can miss novel or shifted messages. Keeping both lets the UI explain disagreement and lets a safety policy respond to corroborated evidence.

## How do you avoid false positives?

The system does not treat every missing authentication result as a failure, uses domain alignment and evidence-family correlation, keeps protective evidence visible, and applies floors only when independent corroboration meets bounded conditions. Those controls reduce selected regressions but do not establish an inbox-wide false-positive rate.

## Why is the threshold still 0.50?

The saved registry threshold is `0.50`. The documented experiments did not meet their promotion gates, so changing the threshold would have changed the model decision policy without sufficient evidence. Decision-safety floors are a separate presentation policy; they do not change the raw ML probability or saved threshold.

## What is calibration?

Calibration maps a model score to a probability-like estimate that better reflects observed frequencies on a calibration boundary. It does not make the classifier universally accurate. The registry records isotonic calibration, and the adapter must preserve the calibrated artifact output.

## How are model artifacts secured?

The versioned registry selects the candidate and records compatibility, calibration, threshold, and hashes. The model manager contains all paths under an approved directory and verifies pipeline, vectorizer, and feature-manifest hashes before deserialization. Private provisioning is separate from user email analysis. Joblib/Pickle is still a trusted artifact boundary, so only reviewed bundles are allowed.

## What happens when ML is unavailable?

When ML is optional, deterministic rule analysis can return with `ml_analysis.status=unavailable`, null ML probabilities, and a qualified completeness state. The safe-verdict guard prevents incomplete analysis from being shown as safely verified. When `ML_REQUIRED=true`, readiness and analysis fail with a service-unavailable response instead.

## Why browser-local history?

History and reports are useful for a local triage workflow without creating a backend database of email. Storage is opt-in, limited to sanitized summaries in the current browser profile, and can be cleared or exported. It is not a shared case-management system.

## How do you handle privacy?

The parser works in memory. The service does not persist raw email or attachment bytes, fetch URLs, render submitted HTML, or execute attachments. Logs and metrics exclude email content, headers, addresses, URLs, credentials, model contents, and local paths. The project still requires authorized input and careful handling in development environments.

## Why did the Microsoft example initially score low?

The text model is limited by its learned vocabulary and distribution. A message can look like a familiar brand impersonation to a rule engine while producing a low ML probability under template or lexical shift. The safe response is to preserve the lower probability and expose the disagreement, not to overwrite the model output.

## What changed in asymmetric safety fusion?

The redesign counts independent evidence families, deduplicates correlated findings, distinguishes protective alignment from high-severity mismatches, and applies bounded floors only when policy markers and minimum families are met. It also blocks a safe presentation when the pipeline is incomplete or critical evidence cannot be verified.

## What would you improve next?

I would add licensed and provenance-complete campaign-grouped data, modern hard negatives, better multilingual and image-aware coverage, independent re-qualification, durable shared rate limiting if needed, an explicit authentication/authorization boundary, and browser/provider-like deployment verification.

## Is the project production-ready?

No. It has production-oriented preparation and security documentation, but no public deployment, production certification, provider capacity validation, Docker/provider-like validation, or private artifact release gate. It should be described as a local defensive research and decision-support project.

## What are the current limitations?

The candidate is text-oriented and inactive, attachment contents are not scanned, live reputation/DNS lookups are not performed, API auth is absent, rate limits and metrics are process-local, trusted artifacts remain executable at load time, and distribution shift and data provenance remain significant. Browser automation is also inconclusive in the recorded host environment.
