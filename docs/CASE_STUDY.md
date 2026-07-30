# PhishPhage AI technical case study

This case study describes the engineering progression using sanitized and synthetic examples. It is a portfolio narrative, not a production certification or a model benchmark.

## Challenge

Email risk is distributed across text, identity, routing, authentication, links, HTML, and MIME structure. A text classifier can be useful, but a single probability is not enough for a high-impact user decision. The system needed to make evidence visible, preserve uncertainty, and avoid storing raw email by default.

## Initial architecture

The first architecture was a browser frontend calling a FastAPI service. The API parsed RFC822/MIME input, ran deterministic rules, invoked a local text model when available, and returned a result. The browser could retain a sanitized summary for history and reports.

## Major failures discovered

Several classes of failure changed the design:

- A rule-only fallback defect could allow incomplete analysis to look too reassuring. Completeness and safe-verdict eligibility had to become explicit states.
- The calibrated wrapper adapter did not initially reconcile with direct artifact inference. An integration repair was needed before the API probability could be trusted as a representation of the existing artifact.
- The rejected SVM candidate improved selected recall diagnostics but failed declared precision/FPR gates. The experiment was not promoted.
- Hybrid structured-feature experiments improved selected diagnostics but also exceeded false-positive or hard-negative budgets. They remained research-only.
- Dataset source dominance, template concentration, incomplete provenance, and campaign gaps limited claims about generalization.

## Inference-integrity bug

The inference audit compared the API path with direct artifact replay. The repaired adapter now aligns the transform, class ordering, calibrated `predict_proba` output, finite-vector checks, registry model/version metadata, and threshold metadata. The repair made the API represent the artifact correctly; it did not make the model more accurate.

## Model limitations

The current registry-selected candidate is a text-oriented calibrated Logistic Regression artifact with a saved threshold of `0.50`, isotonic calibration metadata, `deployment_candidate=true`, and `activated=false`. It does not verify live SPF/DKIM/DMARC, perform reputation lookups, follow redirects, inspect attachment contents, or guarantee multilingual, image-only, compromised-account, novel, or template-shift phishing detection.

## Decision-safety redesign

The redesign separates three ideas:

1. Raw ML probability: preserved exactly for inspection.
2. Deterministic rule score: calculated from observable signals.
3. Presentation safety: determines whether the evidence is complete enough for a safe presentation and whether corroborated independent evidence requires a bounded floor.

The fusion layer deduplicates evidence by identity, routing, authentication, action, and infrastructure families. It uses asymmetric policy: strong corroboration can apply a phishing floor, moderate corroboration can apply a suspicious floor, and incomplete or stale analysis cannot present a safe verdict.

## Safe-verdict protection

The system now distinguishes `eligible`, `needs_review`, `unable_to_verify`, and `rescan_required`. A current result with missing ML, missing rules, failed parsing, contradictory metadata, failed URL extraction, or unverified provenance cannot be presented as safely verified. This protects the user from a reassuring label created by a partial pipeline.

## Sanitized disagreement scenario

The portfolio walkthrough uses a synthetic Microsoft-style impersonation email with an inert `example.org` destination. The current local run returned phishing/100 with raw ML probability 1.0 and applied the `brand_impersonation_with_routing_mismatch` safety floor. This is a scenario-specific demonstration of asymmetric safety fusion, not an accuracy statistic or inbox prevalence estimate.

An earlier portfolio narrative described a separate 82/100 result with raw ML probability 22.9%. That pair was not reproduced by the current fixture and is now treated as an unsupported claim until a distinct, documented synthetic input reproduces it. Do not edit a result image to force the pair.

## Security hardening

The API applies request-size and parser/MIME bounds, exact CORS, request IDs, process-local rate limits, safe error bodies, restrictive security headers, `no-store` API responses, and HSTS when production TLS is assumed. The service does not fetch submitted URLs, render submitted HTML, execute attachments, or persist raw email. Logs and metrics exclude email content, addresses, URLs, credentials, model contents, and local paths.

Model artifacts are a separate supply-chain boundary. Registry selection, path containment, compatibility, manifest checks, and SHA-256 verification happen before deserialization. Joblib/Pickle remains trusted code-loading behavior, so only a reviewed private bundle may be provisioned.

## Observability

Health, readiness, and metrics expose startup, model, request, analysis, inference, rate-limit, and latency status. Structured completion logs include request ID, method, path, status, latency, success, a truncated user agent, and a pseudonymous client identifier. Metrics are process-local and reset on restart; they are not a durable monitoring system.

## Testing

The 2026-07-29 release-candidate validation records 245 backend pytest tests, 33 frontend Node tests, TypeScript, lint, production build, pip check, and npm audit results. The browser security suite remains inconclusive because the host blocked child-process launch with `spawn EPERM`. Provider deployment, Docker execution, HTTPS smoke testing, and private artifact release validation were not performed.

## Final architecture

The final design is browser -> FastAPI -> bounded parser -> rules and optional approved ML -> decision-safety fusion -> typed response. Optional sanitized history remains in the current browser profile. A versioned registry and private provisioning path feed model integrity checks. Health/readiness/metrics and privacy-safe logs expose operational state without email content. Firebase is optional and is not an authorization boundary.

## Limitations

- No public deployment or production certification.
- No API authentication or authorization layer in the current repository.
- Rate limiting and metrics are process-local.
- Trusted model artifacts can execute code at load time.
- The active candidate is inactive and private artifacts are not public repository files.
- Attachment contents are not scanned.
- No live DNS, URL reputation, or external threat-intelligence lookups.
- Data provenance, campaign diversity, language coverage, and distribution shift remain material risks.

## Lessons learned

- A probability is not the same as a safe user-facing decision.
- Safe fallback behavior must be explicit and testable.
- Calibration and adapter integrity are separate concerns from model quality.
- Independent evidence families are more useful for explanation than a long undifferentiated list of rules.
- Failed experiments and data limitations make a stronger engineering story when they remain visible.

## Future roadmap

1. Add licensed, privacy-reviewed, campaign-grouped hard negatives and modern phishing families.
2. Re-run independent qualification with precision, FPR, calibration, and false-negative gates.
3. Decide whether authentication, authorization, and shared rate limiting are required for the deployment context.
4. Restore browser automation and complete provider-like HTTPS, capacity, and startup validation.
5. Reproduce and review the synthetic portfolio captures and the 82/100 disagreement scenario.
