# PhishPhage AI — College Presentation Outline

Target duration: **8–12 minutes**. Use synthetic email only. Describe the
system as an academic/research prototype, not a production-certified product.

## Slide 1 — PhishPhage AI

- Explainable phishing detection with evidence-aware decision safety.
- Academic/research prototype for human-supported email triage.
- Student, college, department, supervisor, and academic year placeholders.

Recommended visual: title card with the project logo and a simple email-to-result arrow.

Speaker notes: Introduce the problem and set the scope boundary immediately:
the system supports human review and does not guarantee protection.

Estimated speaking time: 30 seconds.

## Slide 2 — Problem statement

- Phishing evidence is spread across content, headers, links, and authentication.
- A single label hides why an email looks risky.
- New campaigns can evade simple lists and keywords.
- Sending raw email to third parties raises privacy concerns.

Recommended visual: one synthetic message annotated with evidence families.

Speaker notes: Explain that the project focuses on inspection and reasoning, not
automatic inbox enforcement.

Estimated speaking time: 40 seconds.

## Slide 3 — Objectives

- Parse pasted, raw RFC822, and `.eml` input locally.
- Combine deterministic rules with an optional ML candidate.
- Show score, probability, indicators, and recommendations.
- Support human review and approved-gold evaluation.
- Preserve privacy and document limitations.

Recommended visual: five objective icons or a compact goal diagram.

Speaker notes: Connect each objective to one visible feature in the demo.

Estimated speaking time: 35 seconds.

## Slide 4 — Existing-system limitations

- Blocklists are strongest for known indicators.
- Keyword filters are explainable but can over-alert.
- Opaque models are difficult to challenge.
- External analysis can conflict with privacy requirements.
- Benchmarks can hide source and campaign shift.

Recommended visual: comparison table of blocklist, rules, ML, and hybrid approaches.

Speaker notes: This motivates the hybrid, evidence-first design.

Estimated speaking time: 40 seconds.

## Slide 5 — Proposed PhishPhage AI solution

- Local parsing treats email as untrusted data.
- Rules expose technical and linguistic evidence.
- ML estimates lexical phishing probability.
- Safety fusion keeps strong evidence visible.
- Human verification remains the final operational step.

Recommended visual: three-column Rules + ML + Human Review diagram.

Speaker notes: Emphasize that fusion does not turn a prototype into a guarantee.

Estimated speaking time: 45 seconds.

## Slide 6 — System architecture

- Next.js frontend sends bounded requests to FastAPI.
- Parser feeds rules and feature extraction.
- Registry checks the local candidate before inference.
- Fusion produces an explainable result.
- Dataset Review is a separate local workflow.

Recommended visual: the Mermaid architecture in [ARCHITECTURE.md](ARCHITECTURE.md).

Speaker notes: Point out private/local components, optional Gemini, SQLite
review storage, inactive registry, and the absence of automatic retraining.

Estimated speaking time: 55 seconds.

## Slide 7 — Detection pipeline

- Input modes: Quick Paste, raw source, and `.eml` upload.
- Header/body/HTML-text/URL/attachment metadata extraction.
- Rule signal families and model probability.
- Evidence-aware safety fusion.
- Structured result and recommended next action.

Recommended visual: left-to-right pipeline with one synthetic message.

Speaker notes: State explicitly that URLs are not fetched and attachments are not executed.

Estimated speaking time: 50 seconds.

## Slide 8 — Explainability and indicators

- Identity and routing relationships.
- Authentication pass, fail, inconclusive, or missing state.
- Urgency, credential, payment, and sensitive-action language.
- URL and visible-link structure.
- Model/rule agreement, disagreement, and limited-evidence warnings.

Recommended visual: screenshot of the result signal cards, captured manually.

Speaker notes: Explain why evidence families are more useful than a bare risk label.

Estimated speaking time: 50 seconds.

## Slide 9 — Dataset Review and gold-dataset workflow

- Sanitized evidence enters a local review boundary.
- Gemini is optional, external, and advisory-only.
- Human reviewers record labels and confidence.
- Second review, adjudication, duplicate, and audit controls apply.
- Approved metadata supports offline evaluation and future retraining.

Recommended visual: Pending → Reviewed → Second Review → Approved → Archived state flow.

Speaker notes: Human reviewers remain authoritative; no automatic label or model activation occurs.

Estimated speaking time: 55 seconds.

## Slide 10 — Technology stack

- Next.js, React, TypeScript, and Tailwind CSS.
- FastAPI, Pydantic, and Python MIME parsing.
- scikit-learn Logistic Regression with TF-IDF.
- Browser-local history and local SQLite review storage.
- pytest, Node tests, TypeScript, ESLint, and Next build.

Recommended visual: layered technology-stack blocks.

Speaker notes: Tie each technology to a concrete project responsibility.

Estimated speaking time: 35 seconds.

## Slide 11 — Testing and validation

- Backend tests cover parser, rules, inference, review, exports, and security.
- ML tests cover evaluation and false-negative analysis.
- Frontend tests cover history, reports, and review state.
- TypeScript, lint, build, compile, docs-link, and privacy checks.
- Browser walkthrough and screenshots remain manual evidence.

Recommended visual: test pyramid or validation checklist.

Speaker notes: Report actual command results from the final validation run; do not
replace missing browser evidence with a claim.

Estimated speaking time: 45 seconds.

## Slide 12 — Model results

- Approved records: 75; safe: 25; phishing: 50.
- Accuracy: 0.6667; precision: 0.9630; recall: 0.5200.
- F1: 0.6753; ROC-AUC: 0.8852; PR-AUC: 0.9247.
- Confusion matrix: `[[24, 1], [24, 26]]`.
- Candidate: `phase-c-logistic-regression-v1`, version `1.0.0`, inactive.

Recommended visual: metrics table plus confusion matrix heatmap.

Speaker notes: Explain that precision is high while recall is limited. Do not
say 96% overall accuracy and do not claim guaranteed phishing protection.

Estimated speaking time: 60 seconds.

## Slide 13 — Limitations and future scope

- 24 of 50 approved phishing records were false negatives.
- Ten were in probability band 0.00–0.10; 14 in 0.20–0.30.
- Errors were source/campaign concentrated.
- URL, authentication, and attachment metadata were limited.
- Future work requires more independent, privacy-reviewed, campaign-grouped data.

Recommended visual: limitation-to-future-work two-column table.

Speaker notes: Explain why the current evidence does not justify threshold,
calibration, retraining, or activation changes.

Estimated speaking time: 55 seconds.

## Slide 14 — Conclusion

- PhishPhage AI makes phishing evidence easier to inspect.
- Rules and ML provide complementary signals.
- Human review remains authoritative.
- Privacy and limitations are part of the design.
- The project is ready for academic demonstration as a research prototype.

Recommended visual: final architecture/result summary and “verify independently” reminder.

Speaker notes: Close by restating what the project demonstrates and what it does
not claim. Invite questions about precision, recall, privacy, and future review.

Estimated speaking time: 35 seconds.

## Suggested timing summary

| Segment | Slides | Time |
|---|---|---:|
| Context and objectives | 1–4 | 2:25 |
| Design and live workflow | 5–9 | 3:55 |
| Stack and validation | 10–11 | 1:20 |
| Results and limitations | 12–13 | 1:55 |
| Conclusion | 14 | 0:35 |
| **Total** | **14 slides** | **10:10** |
