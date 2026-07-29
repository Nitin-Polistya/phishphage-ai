# Synthetic demonstration email set

These messages are invented fixtures for screenshots, local walkthroughs, and parser demonstrations. They are not copied from a mailbox or a redistributable dataset. All domains are reserved example domains, all message IDs are fabricated, and no URL should be opened.

## Expected behavior

| Fixture | Intended evidence | Deterministic expectation |
| --- | --- | --- |
| `safe_business_email.eml` | Routine internal note, aligned sender, explicit synthetic authentication passes, no action link | Parser succeeds; rule analysis should contain no high-concern indicator. A safe presentation still requires a current, complete ML/rules fusion. |
| `suspicious_account_alert.eml` | Urgency, account-verification language, reply-to mismatch, and an example-domain destination | Parser succeeds; rule analysis should identify sensitive-action, routing, and destination evidence. Present as review/high concern; never imply the destination was fetched. |
| `phishing_brand_impersonation.eml` | Sanitized Microsoft-style regression: claimed organization, mismatched sender, failed authentication, reply-to mismatch, and a non-live example destination | Parser succeeds; the deterministic safety layer prevents a reassuring safe presentation and applies the `brand_impersonation_with_routing_mismatch` floor. The current local run returned phishing/100 with raw ML probability 1.0; do not substitute the earlier 82/100 and 22.9% narrative without reproducing that separate scenario. |

The expected results describe analysis intent and safety behavior, not a benchmark, prevalence estimate, or universal detection guarantee. When the private model artifact is unavailable, the API should report ML as unavailable and the safe verdict must remain disallowed. The current fixture results were captured with the local approved artifact on 2026-07-29.

## Safe handling

- Use only in a local or otherwise authorized environment.
- Keep the URLs as inert text; do not resolve, click, or fetch them.
- Do not add real brands, personal addresses, raw headers, credentials, or attachment bytes.
- Capture the displayed model/readiness state rather than editing it after capture.
