# Demo guide (2–3 minutes)

Suggested narration:

1. **Problem (20 seconds):** “Suspicious email is difficult to triage quickly because the useful evidence is spread across content, headers, links, and authentication context.”
2. **Landing page (15 seconds):** Point out explainable indicators, local processing, and explicit limitations.
3. **Analyzer (25 seconds):** Open `/analyze`, show the header guidance, privacy notice, character count, and backend/model status.
4. **Safe example (20 seconds):** Click **Use safe example**. Explain that it uses only `example.com` data and no real personal information.
5. **Inference (30 seconds):** Submit and show the indeterminate processing state, then explain the risk score, probability, confidence, model version, and processing time.
6. **Signals (25 seconds):** Walk through signal families, phishing/urgency/authentication/URL groups, and recommendations. Emphasize that URLs are not clickable and no HTML is rendered.
7. **Health (10 seconds):** Show the connection and candidate-model status. Clarify that a deployment candidate is not an activated production model.
8. **Privacy and limits (25 seconds):** Explain in-memory processing, no URL fetching/attachment execution, and why automated analysis supports—not replaces—human review.

Avoid showing real messages, browser storage, secrets, or claims of guaranteed detection.
