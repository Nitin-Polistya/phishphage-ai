# PhishShield AI portfolio demo

Target length: 3-5 minutes. Use only the synthetic fixtures in [`assets/demo/`](assets/demo/) and keep the backend/model state truthful. This is a decision-support demonstration, not a claim of production certification or universal detection.

## Script

### 1. Problem introduction (20 seconds)

“Suspicious email risk is spread across wording, identity, routing, authentication, links, and attachment metadata. PhishShield AI brings those signals into one explainable review surface. The goal is to help a human make a safer next decision, not to replace mail controls or judgment.”

### 2. Landing page (15 seconds)

Open `/`. Point out the three input modes and the in-memory analysis boundary. Say: “The application parses email as data. It does not render submitted HTML, visit URLs, execute attachments, or require Firebase.”

### 3. Input modes (20 seconds)

Open `/analyze`. Show Quick Paste, raw source, and `.eml` upload. Explain that raw RFC822 source adds headers and MIME evidence, while Quick Paste is useful when only visible content is available. Show the size and privacy guidance.

### 4. Safe email scan (25 seconds)

Submit `safe_business_email.eml`. Say: “This is a fully synthetic internal note with an aligned example-domain sender and explicit synthetic authentication passes. The rule layer should find no high-concern indicator.” Show the actual ML/readiness state. If the model is unavailable, say: “The system is honest about that limitation and does not present a safe verdict from incomplete evidence.”

### 5. Phishing impersonation scan (35 seconds)

Submit `phishing_brand_impersonation.eml`. Say: “This fixture is synthetic and uses an inert example destination. It claims Microsoft in the display name and subject, but the sender and reply path do not align with the claim; authentication also fails.” Point to the identity, routing, and authentication indicators.

### 6. ML/rule disagreement (25 seconds)

Open the model detail. Say: “The ML model can disagree with deterministic evidence. The raw ML probability remains visible; the system does not rewrite it to make the story look cleaner.”

### 7. Decision-safety floor (25 seconds)

Open the decision-safety panel. Say: “Because independent evidence families corroborate a sensitive action and unsafe identity/routing, asymmetric fusion can apply a bounded safety floor. In the documented synthetic scenario the final presentation is 82/100 while the raw ML probability remains 22.9%. This is a scenario result, not an accuracy claim.”

### 8. Indicators and recommendations (20 seconds)

Show detailed indicators and recommendations. Say: “Every recommendation is tied to an observable signal: do not click, use the official service directly, verify through an independent channel, and re-scan after obtaining fresh source data.”

### 9. History/reports (20 seconds)

Open `/history` and `/reports`. Say: “History is browser-local and opt-in. It stores a sanitized summary, not raw email or complete raw headers. Reports are generated from those sanitized records and can be cleared or exported.”

### 10. Privacy and security (20 seconds)

Point to the privacy/security documentation. Say: “The API applies request limits, exact CORS, security headers, request IDs, safe errors, and privacy-safe logs. It does not fetch submitted URLs or execute attachment content. Attachment contents are not scanned; only metadata is analyzed.”

### 11. Architecture (20 seconds)

Show `system-architecture.mmd` or its reviewed export. Say: “The browser calls FastAPI. The parser feeds rules and an approved local model. Decision safety fuses evidence, while optional browser-local history remains outside backend persistence. Registry-controlled artifacts are hash-checked before loading. Firebase is optional.”

### 12. Limitations and future work (25 seconds)

“The current model is text-oriented and inactive as a registry candidate until private artifacts and readiness requirements are met. The system does not verify live SPF/DKIM/DMARC, fetch reputation, inspect attachment contents, or guarantee novel or multilingual phishing detection. The repository has not been publicly deployed. Next work includes provenance-complete data, independent qualification, browser verification, deployment validation, and a reviewed decision on authentication and shared rate limiting.”

## Closing line

“PhishShield AI makes uncertainty and evidence visible so a reviewer can slow down a risky action.”
