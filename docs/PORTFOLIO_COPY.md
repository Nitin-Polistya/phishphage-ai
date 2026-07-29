# Portfolio copy

All copy below is scoped to the repository evidence and the synthetic demonstration scenario. Do not add claims about deployment, adoption, universal accuracy, or commercial outcomes.

## Resume bullets

### A. Concise

- Built PhishShield AI, a Next.js/FastAPI phishing-analysis platform that combines local email parsing, deterministic evidence, calibrated ML inference, and decision-safety explanations for human review.

### B. Standard

- Built a Next.js and FastAPI platform that analyzes Quick Paste, RFC822, and `.eml` email inputs across content, headers, links, authentication evidence, and attachment metadata.
- Implemented registry-controlled calibrated Logistic Regression inference, artifact hash validation, rule/ML agreement reporting, and asymmetric evidence-aware safety floors while preserving raw ML probability.
- Added privacy and security controls including in-memory processing, opt-in browser-local sanitized history, bounded requests, exact CORS, CSP/security headers, safe errors, request IDs, rate limits, readiness, metrics, and privacy-safe logs.

### C. Technical

- Designed a browser-to-FastAPI analysis pipeline with bounded RFC822/MIME parsing, visible-HTML text extraction, offline domain comparison, URL evidence classification, and attachment-metadata-only inspection.
- Repaired a calibrated-model adapter mismatch by aligning API inference with the verified artifact's transform, class ordering, probability shape, calibration metadata, and registry threshold.
- Implemented evidence-family fusion that retains raw ML probability and uses deterministic identity, routing, authentication, action, and infrastructure corroboration to prevent unjustified safe presentations.
- Secured model loading with registry selection, approved-directory containment, SHA-256 validation for pipeline/vectorizer/manifest assets, compatibility checks, and fail-closed behavior for unavailable or inconsistent artifacts.
- Documented and verified the latest checked-in validation snapshot of 218 backend pytest tests and 28 frontend Node tests, while recording browser-launch, deployment, provider, and model-artifact release limitations.

## Short LinkedIn project description

PhishShield AI is an explainable phishing-analysis platform built with Next.js and FastAPI. It parses email locally, surfaces deterministic evidence, optionally uses a registry-controlled calibrated text model, and applies decision-safety checks so reviewers can see uncertainty instead of receiving a misleadingly confident safe verdict.

## Long LinkedIn project post

I built PhishShield AI to explore a practical question in email security: what should a tool do when a statistical model and strong deterministic evidence disagree?

The project combines a Next.js interface with a FastAPI analysis service. It accepts Quick Paste, raw RFC822, and `.eml` inputs; parses headers, body text, links, authentication results, and attachment metadata; and returns structured evidence with recommendations.

The most important design decision was to keep the raw calibrated ML probability visible. A model can be uncertain or wrong, especially under template shift. Deterministic evidence can still establish that a message needs review. The safety layer therefore uses independent identity, routing, authentication, action, and infrastructure families to block unjustified safe presentations and apply bounded floors when corroboration is strong.

The project also includes artifact hash validation, registry-controlled model loading, privacy-safe logs, bounded requests, security headers, readiness and metrics endpoints, and opt-in browser-local sanitized history. Firebase remains optional, attachment contents are not scanned, and the repository has not been publicly deployed.

The latest checked-in evidence records 218 backend tests and 28 frontend tests. The remaining work is deliberately visible: better provenance-complete data, independent qualification, browser verification, deployment validation, and a reviewed decision on authentication and shared rate limiting.

## GitHub repository description

Explainable phishing analysis with local email parsing, deterministic evidence, optional calibrated ML, and evidence-aware decision safety for human review.

## Portfolio-card description

PhishShield AI turns suspicious email into an evidence-backed review workflow. The project demonstrates privacy-conscious RFC822/MIME parsing, rule/ML fusion, model artifact integrity checks, safety floors, browser-local history, and operational safeguards without claiming universal detection or public deployment.

## Interview elevator pitch

“PhishShield AI is a Next.js/FastAPI email-analysis workspace. It parses email locally, extracts explainable signals, optionally runs a calibrated text classifier, and then keeps model and rule evidence separate so a safety layer can prevent a false reassurance when independent evidence is concerning. I treated model integrity, privacy, and uncertainty as first-class product behavior, and documented the limits rather than hiding failed experiments.”

## Professor or project-review summary

This project investigates how a defensive email-analysis system can combine a text classifier with deterministic security evidence while maintaining an explicit privacy and safety boundary. The implementation covers parsing, rule analysis, calibrated inference, model artifact verification, decision-safety fusion, observability, browser-local retention, and security middleware. The research record includes an inference integration defect, a rejected SVM candidate, rejected hybrid-feature experiments, and dataset provenance limitations. The contribution is not a claim of universal phishing accuracy; it is a reproducible engineering study of evidence-aware analysis and safe presentation under uncertainty.

## Claim hygiene

- Use “latest checked-in evidence: 218 backend and 28 frontend tests” unless a new run produces a reviewed result.
- Do not publish “245 backend and 33 frontend tests” from this phase; that milestone is not supported by the current repository evidence.
- Use the 82/100 and 22.9% pair only as the labeled synthetic decision-safety scenario described in [CASE_STUDY.md](CASE_STUDY.md), after reproducing it locally for a screenshot or talk.
- Never use “production-ready,” “deployed,” “enterprise,” “commercial,” “100% accurate,” or “detects all phishing.”
