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
| `openai_mandrill_subscription.eml` | safe |
| `unstop_moengage_promotion.eml` | safe or suspicious |

None may be classified as phishing.
