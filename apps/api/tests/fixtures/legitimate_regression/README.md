# Legitimate-email regression fixtures

These `.eml` files are synthetic, sanitized structural fixtures. They preserve the
header and MIME patterns needed to test legitimate bulk and transactional mail,
but contain no real recipient identifiers, provider tokens, or usable tracking
identifiers. Analysis must remain local: tests never fetch URLs, render HTML, or
decode/execute attachments.

The fixtures are regression inputs only and must not be included in ML training.

Expected outcomes:

| Fixture | Expected final classification |
| --- | --- |
| `cline_hubspot_newsletter.eml` | safe |
| `github_education_approval.eml` | safe |
| `gmail_inbox_welcome.eml` | safe |
| `gmail_inbox_welcome_missing_auth.eml` | safe, qualified as limited authentication evidence |
| `openai_mandrill_subscription.eml` | safe |
| `unstop_moengage_promotion.eml` | safe or suspicious |

None may be classified as phishing.

The missing-authentication Gmail fixture is intentionally separate from the
authenticated structural fixture. It preserves transport headers while omitting
`Authentication-Results`, `Received-SPF`, and `DKIM-Signature`.
