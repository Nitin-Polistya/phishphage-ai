# Synthetic demonstration email set

These messages are invented fixtures for screenshots, local walkthroughs, and parser demonstrations. They are not copied from a mailbox or a redistributable dataset. All domains are reserved example domains, all message IDs are fabricated, and no URL should be opened.

## Expected behavior

| Fixture | Intended evidence | Deterministic expectation |
| --- | --- | --- |
| `safe_business_email.eml` | Routine internal note, aligned sender, explicit synthetic authentication passes, no action link | Parser succeeds; rule analysis should contain no high-concern indicator. A safe presentation still requires a current, complete ML/rules fusion. |
| `suspicious_account_alert.eml` | Urgency, account-verification language, reply-to mismatch, and an example-domain destination | Parser succeeds; rule analysis should identify sensitive-action, routing, and destination evidence. Present as review/high concern; never imply the destination was fetched. |
| `phishing_brand_impersonation.eml` | Sanitized Microsoft-style regression: claimed organization, mismatched sender, failed authentication, reply-to mismatch, and a non-live example destination | Parser succeeds; the deterministic safety layer should preserve the lower raw ML probability while preventing a reassuring safe presentation. The portfolio scenario records a final 82/100 result with raw ML probability 22.9%; reproduce locally before using the numeric pair in a capture. |

The expected results describe analysis intent and safety behavior, not a benchmark, prevalence estimate, or universal detection guarantee. When the private model artifact is unavailable, the API should report ML as unavailable and the safe verdict must remain disallowed.

## Safe handling

- Use only in a local or otherwise authorized environment.
- Keep the URLs as inert text; do not resolve, click, or fetch them.
- Do not add real brands, personal addresses, raw headers, credentials, or attachment bytes.
- Capture the displayed model/readiness state rather than editing it after capture.
