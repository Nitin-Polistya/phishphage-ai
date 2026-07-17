# Facebook Impersonation Regression

The permanent safe fixture is `apps/api/tests/fixtures/facebook_security_impersonation.eml`. It uses only reserved `example.com`, `example.net`, and `example.org` domains. No destination is fetched.

## Before Step 2

For the exact sanitized body-only text now used by the regression, the Step 1 model returned phishing probability 0.270710 at threshold 0.35, predicted legitimate, triggered no rules, and fused to Safe with 0.84 confidence. This reproduced the reported failure: copied visible text omitted sender, transport headers, HTML source, and the real anchor destination.

The earlier complete-RFC baseline used the same impersonation/header/hidden-link structure with a prior body wording revision. Existing rules found display-name impersonation, Reply-To mismatch, Return-Path mismatch, missing authentication, and URL context; rule risk was 80 and the fused result was Phishing. Its ML probability was only 0.351560. This complete-input comparison is directionally useful but is not claimed as an exact text A/B.

## After Step 2

For the exact body-only regression text, model v2 returns phishing probability 0.899 at threshold 0.50 and predicts phishing. With no rule evidence, fusion returns Suspicious at 0.73 confidence, `body_text_only`, and an explicit limited-evidence warning.

For the complete `.eml`, model v2 returns phishing probability 0.970. Rules now also detect `url_trusted_text_unrelated_destination` by comparing visible `facebook.com` text with the actual `example.net` href. Rule risk is 100; rules and ML agree; the fused result is Phishing at 0.96 confidence with `complete_raw_email` evidence state.

Permanent tests verify local HTML parsing, hidden-destination detection, complete-input evidence, limited Safe qualification, and confidence capping. Complete raw input is still preferred because body-only text cannot establish sender authenticity or reveal hidden HTML destinations.
