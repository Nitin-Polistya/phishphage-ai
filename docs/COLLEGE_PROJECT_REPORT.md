# PhishPhage AI

## Explainable phishing detection with evidence-aware decision safety

**Academic project report — research prototype**

| Field | Placeholder |
|---|---|
| Student name | `[Student name]` |
| Enrollment number | `[Enrollment number]` |
| University / college | `[University or college]` |
| Department | `[Department]` |
| Supervisor | `[Supervisor name]` |
| Academic year | `[Academic year]` |

> PhishPhage AI is an academic/research prototype. It is not production
> certified, does not guarantee phishing protection, and is not a replacement
> for enterprise security controls or human verification.

## Certificate

This is a placeholder for the institution's certificate stating that the work
was completed by `[Student name]` under the supervision of `[Supervisor name]`
for the academic year `[Academic year]`.

## Declaration

I, `[Student name]`, declare that this project report describes work completed
for academic purposes. Institutional wording, signatures, and dates must be
added by the student and college before submission.

## Acknowledgement

This section is reserved for the student's acknowledgement of the supervisor,
department, institution, peers, and family. No institutional or personal
details are fabricated in this repository.

## Abstract

Phishing messages combine social engineering with technical evidence such as
sender identity, routing, authentication, links, HTML, and attachments. That
evidence is often difficult for a person to inspect quickly and safely.
PhishPhage AI is a defensive academic prototype that parses email locally,
extracts explainable indicators, applies deterministic rules, and optionally
uses a registry-controlled text machine-learning candidate. A decision-safety
layer keeps the raw model probability visible while preventing strong,
independent evidence from being hidden by a reassuring model score. The web
interface provides analysis, history, reports, health status, and a local
human-in-the-loop dataset-review workspace.

The current approved-gold evaluation contains 75 records: 25 safe and 50
phishing. At the fixed 0.50 threshold, the model reports 0.6667 accuracy,
0.9630 precision, 0.5200 recall, 0.6753 F1, 0.8852 ROC-AUC, and 0.9247 PR-AUC.
The result demonstrates a precision-oriented candidate with an important
recall limitation: 24 of 50 approved phishing records are false negatives.
The evaluation therefore supports research discussion, not a production claim.
Human reviewers remain authoritative, Gemini is optional and advisory-only, and
private review artifacts remain local.

## Table of contents

1. [Introduction](#introduction)
2. [Problem statement](#problem-statement)
3. [Project objectives](#project-objectives)
4. [Scope](#scope)
5. [Existing systems and limitations](#existing-systems-and-limitations)
6. [Proposed solution](#proposed-solution)
7. [Functional requirements](#functional-requirements)
8. [Non-functional requirements](#non-functional-requirements)
9. [System architecture](#system-architecture)
10. [Technology stack](#technology-stack)
11. [Frontend design](#frontend-design)
12. [Backend/API design](#backendapi-design)
13. [Email parsing pipeline](#email-parsing-pipeline)
14. [Rule-based detection](#rule-based-detection)
15. [Machine-learning pipeline](#machine-learning-pipeline)
16. [Feature engineering](#feature-engineering)
17. [Explainability](#explainability)
18. [Dataset sources and provenance](#dataset-sources-and-provenance)
19. [Privacy and sanitization](#privacy-and-sanitization)
20. [Human-in-the-loop review](#human-in-the-loop-review)
21. [Gold dataset workflow](#gold-dataset-workflow)
22. [Model evaluation](#model-evaluation)
23. [False-negative analysis](#false-negative-analysis)
24. [Testing strategy](#testing-strategy)
25. [Security considerations](#security-considerations)
26. [Results](#results)
27. [Limitations](#limitations)
28. [Future scope](#future-scope)
29. [Conclusion](#conclusion)
30. [References](#references)
31. [Appendix](#appendix)

## Introduction

Email remains a practical delivery channel for credential theft, payment
fraud, malware distribution, and account takeover attempts. Phishing detection
is difficult because the same message can contain natural language, identity
claims, routing data, authentication results, links, HTML, and attachment
metadata. A useful academic system should expose that evidence rather than
returning only an unexplained label.

PhishPhage AI was developed as a privacy-conscious investigation workspace. It
accepts Quick Paste, raw RFC822 source, and `.eml` files. The service parses
email as data, does not render submitted HTML, does not fetch URLs, and does
not execute attachments. It returns a structured analysis for a human to
verify.

## Problem statement

A user needs to decide whether an email deserves caution, but:

- risk evidence is distributed across several email fields;
- a text classifier can miss unfamiliar campaigns or non-lexical evidence;
- a rules-only system can overreact to ordinary account or payment language;
- opaque predictions are difficult to challenge or learn from;
- sending raw email to external services creates privacy and governance risk;
- a benchmark can look strong while hiding source, campaign, and metadata bias.

The project addresses these problems as an academic prototype. It does not
claim to solve general inbox security.

## Project objectives

1. Parse common email inputs locally and safely.
2. Extract indicators that a reviewer can inspect.
3. Combine deterministic evidence with an optional ML probability.
4. Show model, rule, fusion, and recommendation context together.
5. Preserve privacy by limiting stored and exported information.
6. Support label review, adjudication, and approved-gold workflows.
7. Measure performance with explicit dataset boundaries.
8. Document limitations and future retraining requirements honestly.

## Scope

### In scope

- RFC822/MIME parsing and bounded input handling.
- Header, body, HTML-text, URL-structure, and attachment-metadata analysis.
- Rule-based phishing indicators and evidence-aware safety fusion.
- A word TF-IDF Logistic Regression candidate under model-registry checks.
- Browser-local sanitized history and report generation.
- Local Dataset Review, human labels, gold-dataset metrics, and exports.
- Optional sanitized Gemini suggestions that remain advisory.
- Automated backend, ML, frontend, and documentation checks.

### Out of scope

- Production certification or guaranteed detection.
- Live URL reputation lookups or URL fetching.
- Attachment execution, sandboxing, or content scanning.
- Automatic model retraining or model activation.
- Automatic acceptance of Gemini suggestions or source labels.
- Authentication/authorization as a complete enterprise control.
- Processing of private datasets in public documentation.

## Existing systems and limitations

Traditional blocklists are effective for known indicators but can miss new
campaigns. Keyword filters are easy to explain but can produce false positives.
Large neural classifiers may require more data, compute, and governance than an
academic prototype can justify. External analysis services can provide useful
signals but may conflict with a privacy boundary.

These limitations motivate a hybrid design: deterministic evidence for
inspection, a small calibrated candidate for learned lexical patterns, and a
human reviewer for consequential decisions.

## Proposed solution

PhishPhage AI uses the following sequence:

1. The frontend sends bounded email input to the FastAPI API.
2. The parser normalizes and extracts safe structural content.
3. The rule engine identifies independent evidence families.
4. Feature extraction builds the text representation and observational data.
5. The registry loader verifies the local ML candidate before inference.
6. Fusion evaluates corroboration, protective evidence, and limited evidence.
7. The API returns score, probability, classification, signals, and guidance.
8. The user verifies the message through a trusted out-of-band channel.

The current model prioritizes precision and low false positives. Recall remains
lower and is treated as an identified limitation rather than hidden by a
threshold change.

## Functional requirements

| ID | Requirement | Implementation evidence |
|---|---|---|
| FR-01 | Accept pasted, raw, and `.eml` email | Analyze workspace and parser API |
| FR-02 | Extract safe headers and body text | Local MIME parser |
| FR-03 | Identify suspicious evidence | Rule engine and signal families |
| FR-04 | Provide optional ML probability | Registry-controlled inference |
| FR-05 | Explain the result | Indicators, evidence, and recommendations |
| FR-06 | Keep history opt-in | Browser-local sanitized scan records |
| FR-07 | Support review and adjudication | Dataset Review and Gold Dataset pages |
| FR-08 | Export only approved metadata | Privacy-safe gold export workflow |
| FR-09 | Expose operational status | Health, readiness, and metrics endpoints |

## Non-functional requirements

- **Safety:** submitted HTML is not rendered; URLs are not fetched; attachments
  are not executed.
- **Privacy:** raw bodies, full headers, addresses, URLs, and private review
  records are excluded from public reports.
- **Explainability:** every visible conclusion should point to an evidence
  family or an explicit model/fusion state.
- **Reproducibility:** registry metadata, hashes, fixed threshold, and dataset
  roles are documented.
- **Availability:** the API can return deterministic rule analysis when the ML
  candidate is unavailable, without inventing a probability.
- **Maintainability:** frontend, API, and ML tests can run independently.

## System architecture

The tracked diagram in [ARCHITECTURE.md](ARCHITECTURE.md) shows the runtime
analysis path and the separate dataset-review path. The runtime path is:

`User -> Next.js frontend -> FastAPI API -> Email parser -> Rule-based analyzer -> Feature extraction -> ML inference -> Fusion/explainability -> Result`

The review path is deliberately separate:

`Dataset Review -> Sanitization -> optional Gemini advisory suggestion -> human reviewer -> gold dataset -> offline evaluation/future retraining`

Private/local components include the review SQLite store, private approved
exports, and provisioned model artifacts. Gemini is optional. There is no
automatic retraining and no automatic model activation.

## Technology stack

| Layer | Technology | Role |
|---|---|---|
| Web UI | Next.js 15, React 19, TypeScript | Analysis and review workspaces |
| Styling | Tailwind CSS and local UI components | Consistent accessible interface |
| API | FastAPI and Pydantic | Typed request/response boundary |
| Parsing | Python email/MIME tooling | In-memory bounded email parsing |
| ML | scikit-learn, Joblib, NumPy, SciPy | Candidate inference and metrics |
| Storage | Browser storage and local SQLite review store | Opt-in history and local review state |
| Validation | pytest, Node test runner, TypeScript, ESLint, Next build | Automated checks |
| Optional assistant | Gemini through a sanitized advisory path | Review support only |

## Frontend design

The frontend exposes a landing page and an application shell with routes for
Dashboard, Analyze Email, Scan History, Reports, Dataset Review, and Settings.
The Analyze page presents input modes, backend/model status, evidence, scores,
recommendations, and limitations. History and reports use sanitized browser
records only when the user opts in. Dataset Review requires its local feature
configuration and token boundary; it is not a public training interface.

The UI avoids making external destinations clickable during analysis and keeps
model probability, rule evidence, and safety-fusion effects distinguishable.

## Backend/API design

The API has health routes at `/health`, `/ready`, and `/metrics`, versioned
analysis routes under `/api/v1`, parser preview support, and Dataset Review
routes. The main analysis operations are:

- `POST /api/v1/analysis/preview` for the unified mode-aware workflow.
- `POST /api/v1/analyze` for the production raw-email contract.
- `POST /api/v1/parser/preview` for parser inspection.
- `GET /api/v1/dataset-review/status` for review feature status.
- `GET /api/v1/dataset-review/gold-dataset/dashboard` for local gold metrics.
- `POST /api/v1/dataset-review/gold-dataset/export` for approved-only export.

Interactive API documentation is available at the FastAPI `/docs` route when
the local backend is running. Errors are bounded and safe, responses use
request IDs and no-store behavior, and rate limits are process-local.

## Email parsing pipeline

The parser accepts raw MIME/RFC822 data and `.eml` uploads. It extracts headers,
plain text, visible HTML text, URL structure, and attachment metadata while
respecting size, header, MIME, URL, and attachment bounds. It treats the input
as untrusted data. HTML is not rendered, link destinations are not contacted,
and attachments are not executed.

The parser's output is an intermediate representation. It is not a ground-truth
label and is not itself a claim that an email is malicious.

## Rule-based detection

Deterministic indicators are grouped into evidence families so a reviewer can
see why a result was produced. Examples include:

- identity and claimed-organization mismatch;
- sender, Reply-To, Return-Path, and routing relationships;
- authentication states such as pass, fail, inconclusive, or missing;
- urgency, credential, payment, and sensitive-action language;
- visible-link and target mismatch;
- suspicious URL structure, shortened domains, punycode, or IP hosts;
- HTML and attachment metadata signals.

Missing authentication is not automatically treated as failure. Stronger
independent evidence can raise the presentation classification while the raw
ML probability remains visible. Protective evidence is narrow and cannot
override corroborated malicious evidence.

## Machine-learning pipeline

The current registry candidate is `phase-c-logistic-regression-v1`, version
`1.0.0`. It uses word TF-IDF text representation and Logistic Regression with
the saved threshold `0.50`. Registry metadata, compatibility, feature
manifest, and artifact hashes are verified before loading. The registry record
is not activated.

The model is one input to human review. A missing candidate must not result in
a fabricated probability. Experimental SVM, hybrid-feature, and low-threshold
results remain research-only and are not presented as the deployed model.

## Feature engineering

The approved fitted pipeline is text-oriented. The service also exposes
observational structured features for explanation and research diagnostics,
including authentication, organization, financial, credential, urgency,
infrastructure, URL, HTML, and attachment groups. These observations should
not be confused with features fitted into the current production candidate.

This distinction prevents a report from claiming that every visible indicator
changed the trained model decision.

## Explainability

The result screen reports a classification, score, raw phishing probability,
confidence/limited-evidence state, model metadata, rule signals, fusion context,
and recommended next steps. This makes it possible to ask whether a conclusion
came from lexical model evidence, deterministic evidence, or the decision-safety
policy. Explanations support review; they do not prove intent or guarantee
correctness.

## Dataset sources and provenance

The repository documents distinct dataset roles:

| Boundary | Role | Public treatment |
|---|---|---|
| Development/training pool | Candidate development and feature work | Aggregates and provenance only |
| Validation/model-selection data | Candidate comparison and fixed threshold review | Separate from final evaluation |
| External evaluation | Post-lock evidence | Report metrics without raw messages |
| Approved gold data | Human-reviewed benchmark and error analysis | Private records; approved metadata only |
| Synthetic fixtures | Demonstration, parser, and regression tests | Tracked with reserved domains |
| Generated reports | Reproducibility and audit evidence | Sanitized and repository-appropriate only |
| Model artifacts | Local/private runtime inputs | Not redistributed in this report |

Source labels are not automatically trusted as ground truth. Spam, malware,
scam, and other social-engineering categories are not silently mapped to
phishing. Licensing, privacy, exact/normalized/near-duplicate review, campaign
grouping, and split isolation are separate controls.

## Privacy and sanitization

The project keeps raw email and private review artifacts local. Public material
uses aggregate counts, stable digests, redacted metadata, and synthetic
fixtures. It excludes raw message bodies, full addresses, complete URLs from
private datasets, Message-IDs, attachment bytes, tokens, API keys, and private
SQLite output locations.

The optional Gemini path receives sanitized evidence only when enabled. Gemini
does not determine the production label, does not change the gold label, and
does not activate a model. Human reviewers remain authoritative.

## Human-in-the-loop review

Dataset Review provides a bounded local workflow for importing candidate
metadata, reviewing sanitized evidence, recording a human label and confidence,
requesting a second review, and retaining an audit trail. Reviewers should
verify sensitive requests through a trusted official channel rather than
following the message's instructions.

The review workspace is a research control, not a shortcut around privacy,
provenance, or adjudication.

## Gold dataset workflow

The gold workflow separates review state from source claims and model output.
It supports duplicate checks, reviewer decisions, agreement metrics, state
transitions, immutable audit history, and approved-only exports. The intended
state progression is:

`Pending -> Reviewed -> Needs Second Review -> Approved -> Archived`

Human decisions are required for approval. Gemini recommendations, if present,
are advisory provenance. No gold export triggers retraining, calibration,
threshold tuning, registry mutation, or deployment.

## Model evaluation

The following values are the current approved-gold evaluation specified for this
submission. They are reproduced as aggregate results from the verified
approved-gold evaluation bundle; raw records and private generated artifacts
are not included here. The positive class is phishing; the threshold is fixed
at 0.50.

| Metric | Value |
|---|---:|
| Approved records | 75 |
| Safe | 25 |
| Phishing | 50 |
| Accuracy | 0.6667 |
| Precision | 0.9630 |
| Recall | 0.5200 |
| F1 | 0.6753 |
| ROC-AUC | 0.8852 |
| PR-AUC | 0.9247 |
| Brier score | 0.2452 |
| Confusion matrix | `[[24, 1], [24, 26]]` |
| False positives | 1 |
| False negatives | 24 |
| Threshold | 0.50 |
| Model ID | `phase-c-logistic-regression-v1` |
| Model version | `1.0.0` |
| Registry activated | false |

Accuracy is the share of correct classifications. Precision measures how often
positive predictions were correct. Recall measures how many phishing records
were found. ROC-AUC measures ranking across thresholds; PR-AUC is especially
useful when the positive class is the operational concern. The Brier score
measures probability error, so it should not be interpreted as accuracy.

The matrix uses the order `[[true safe, false positive], [false negative,
true phishing]]`. The high precision and lower recall reflect a conservative
candidate and do not support a claim of general inbox performance.

## False-negative analysis

The approved-gold error analysis found 24 false negatives among 50 phishing
records. The probability bands were:

- 10 records in the `0.00–0.10` band;
- 14 records in the `0.20–0.30` band.

The false negatives were concentrated by source and campaign. Retained URL,
authentication, and attachment metadata were limited, so the analysis cannot
attribute those errors to missing or suspicious values in those fields. This is
a limitation of the retained evaluation evidence, not proof that the original
messages lacked those properties.

The current evidence does not justify a deployment-model change. Lowering the
threshold, fitting a new calibrator, retraining, or activating a candidate would
require a separately governed experiment with more independent, privacy-safe,
campaign-grouped data and explicit false-positive controls.

## Testing strategy

The project uses layered tests:

1. Backend unit and API tests cover parsing, rules, inference contracts,
   decision safety, review storage, exports, and security controls.
2. ML tests cover evaluation, error analysis, dataset schemas, and deterministic
   diagnostics.
3. Frontend tests cover history, reports, input handling, dataset-review state,
   and security policy behavior.
4. TypeScript, ESLint, and Next.js build checks validate the web application.
5. Documentation link, whitespace, compile, and privacy scans protect the
   submission package.
6. Browser-based demonstration validation is a manual step when a browser
   target is available; this environment did not expose one.

Tests are evidence for the implementation under test, not proof of universal
phishing detection.

## Security considerations

- Treat every email as untrusted input.
- Bound HTTP bodies and parser/MIME work.
- Do not render arbitrary submitted HTML.
- Do not fetch or resolve URLs.
- Do not execute or inspect attachment content automatically.
- Use safe errors and request IDs without logging message content.
- Keep model artifacts behind hash and registry checks.
- Keep optional review storage local and token values out of the frontend.
- Keep browser history opt-in and sanitized.
- Recheck claims, provenance, and privacy before sharing screenshots or reports.

The project does not claim that a local prototype is a complete enterprise
security boundary. Users must independently verify requests involving
credentials, payments, downloads, or account changes.

## Results

The implementation provides a complete academic demonstration path: a user can
open the landing page, inspect the architecture, check API status, analyze
synthetic safe and phishing fixtures, inspect indicators and recommendations,
review local history and reports, and explain the Dataset Review and gold-data
workflow. The evaluation is strongest as an illustration of the precision/
recall trade-off and the value of transparent error analysis.

### Results interpretation

| Observation | Academic interpretation |
|---|---|
| Precision 0.9630 | The candidate was conservative about positive predictions on this set. |
| Recall 0.5200 | Many approved phishing records were missed; this is the main limitation. |
| One false positive | Low false-positive count is useful but not a general guarantee. |
| 24 false negatives | Further independent data and error analysis are necessary. |
| ROC-AUC/PR-AUC above point accuracy | Ranking quality and thresholded classification answer different questions. |
| Registry inactive | The evidence did not justify production activation. |

## Limitations

| Limitation | Effect | Responsible interpretation |
|---|---|---|
| Small approved-gold set | Estimates have uncertainty | Research evidence only |
| Source/campaign concentration | Generalization may be overstated | Expand independent campaign coverage |
| Low recall | Phishing can be missed | Verify every sensitive request |
| Limited retained metadata | Error causes cannot always be isolated | Preserve lawful structural metadata in future review |
| English/template emphasis | Multilingual and novel attacks are under-qualified | Do not claim multilingual coverage |
| Synthetic demonstrations | UI behavior is repeatable, not realistic prevalence | Use only for local presentation |
| Inactive model registry | No production approval exists | Describe as a candidate |
| Optional Gemini dependency | Live review assistance may be unavailable | Demo must work without Gemini |

## Future scope

| Future work | Required evidence or control |
|---|---|
| Expand approved gold data | Independent sources, privacy review, provenance, two-reviewer adjudication |
| Improve recall | New campaign families and controlled threshold experiments |
| Preserve richer metadata | Lawful URL/authentication/attachment fields with redaction |
| Evaluate multilingual mail | Language-separated, campaign-grouped external holdout |
| Compare model families | Predeclared precision, recall, FPR, calibration, and hard-negative gates |
| Improve review ergonomics | Human factors testing without changing label authority |
| Consider retraining | Separate change review, hashes, rollback, and activation gate |

None of these future items is enabled by this documentation phase.

## Conclusion

PhishPhage AI demonstrates how a small explainable phishing-analysis system can
combine local parsing, deterministic evidence, machine-learning inference, and
human review without hiding its uncertainty. Its current approved-gold result
shows a precision-oriented candidate with a meaningful recall gap. That gap is
the central conclusion, not a reason to make a production claim.

The project is therefore suitable for college presentation as a research
prototype. It has a clear architecture, reproducible local workflow, privacy
controls, review governance, and documented next steps. A production decision
would require new evidence and a separately approved engineering phase.

## References

1. RFC 5322, *Internet Message Format*, Internet Engineering Task Force.
2. FastAPI project documentation and OpenAPI conventions used by the API.
3. Next.js App Router documentation used by the frontend.
4. scikit-learn User Guide, Logistic Regression, TF-IDF, classification metrics,
   ROC-AUC, PR-AUC, and calibration.
5. Repository documentation: [Architecture](ARCHITECTURE.md), [API](API.md),
   [Model](MODEL.md), [Datasets](DATASETS.md), [Evaluation](EVALUATION.md),
   [Security](SECURITY.md), and [Testing](TESTING.md).
6. Repository source and tests for the PhishPhage AI academic prototype.

## Appendix

### A. API endpoints

| Area | Endpoint |
|---|---|
| Health | `GET /health`, `GET /ready`, `GET /metrics` |
| Versioned health | `GET /api/v1/health` |
| Parser | `POST /api/v1/parser/preview` |
| Analysis preview | `POST /api/v1/analysis/preview` |
| Raw analysis | `POST /api/v1/analyze` |
| Dataset status | `GET /api/v1/dataset-review/status` |
| Gold dashboard | `GET /api/v1/dataset-review/gold-dataset/dashboard` |
| Gold agreement | `GET /api/v1/dataset-review/gold-dataset/agreement` |
| Gold export | `POST /api/v1/dataset-review/gold-dataset/export` |

### B. Startup commands

Backend:

```powershell
cd D:\Development\Projects\phishphage-ai\apps\api
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd D:\Development\Projects\phishphage-ai\apps\web
npm run dev -- -p 3000
```

Use port `3001` for the frontend if `3000` is busy.

### C. Test commands

```powershell
.\apps\api\.venv\Scripts\python.exe -m pytest -q apps/api/tests
python -m pytest -q services/ml/tests
cd apps/web
npm test
npx tsc --noEmit
npm run lint
npm run build
```

### D. Screenshots and presentation assets

See [COLLEGE_SCREENSHOT_PLAN.md](COLLEGE_SCREENSHOT_PLAN.md). Screenshots,
screen recordings, student details, institutional signatures, and final
browser-run evidence remain manual deliverables. Only synthetic inputs may be
shown.
