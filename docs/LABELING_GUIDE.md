# Manual labeling guide

This guide defines ground truth for the three-class evaluation schema. Labels
must be based on available message evidence and source context, never on a
PhishPhage prediction, threshold, rule score, filename, or dataset shortcut.

## Safe

Use `safe` when the sender/context is legitimate, there is no deceptive
impersonation, and there is no credential, payment, account-takeover, or other
social-engineering objective. Expected business or personal communication,
including promotional content, can be safe. Legitimate third-party sending
infrastructure is not itself suspicious when the message and context support
the claimed relationship.

## Suspicious

Use `suspicious` when evidence is incomplete or conflicting: a questionable
sender or destination, spam-like or deceptive behavior without a verified
phishing objective, malformed evidence, or an unresolved question requiring
analyst review. Suspicious is not a weaker synonym for phishing.

## Phishing

Use `phishing` only when evidence supports harmful deception: a deceptive
identity or sender claim, credential theft, payment fraud, account takeover,
malicious or deceptive link/action, harmful impersonation, verified social
engineering, malicious attachment delivery, or a confirmed phishing campaign.

## Boundary cases

- Generic spam is not phishing unless it has a supported deceptive or harmful
  objective.
- Ordinary marketing can be safe; brand impersonation or a deceptive action
  request can be phishing.
- Newsletter format alone is not evidence of phishing; compare sender, links,
  authentication, and context.
- Business email compromise is phishing when impersonation or fraudulent
  payment/data action is supported; otherwise use suspicious if incomplete.
- An authentic security alert or password reset with expected destinations is
  safe; a spoofed alert is phishing; unclear evidence is suspicious.
- Graymail, malformed-but-benign mail, mailing-list artifacts, and unusual
  formatting are not phishing by themselves.
- Phishing simulations and forwarded phishing reports should be excluded or
  kept in separate categories unless the underlying evidence is reviewable.
- A compromised legitimate account can still send phishing; label the harmful
  objective, not merely the account's authenticity.
- Suspicious but inconclusive messages remain suspicious. Never invent a label
  to satisfy class balance.

## Review protocol

Reviewer 1 and reviewer 2 record labels independently, confidence, and notes.
Disagreements require a reason. An adjudicator records the final label, notes,
reviewer identity, and date. One available reviewer creates a **provisional**
record only and cannot support headline metrics. Notes must not contain raw
bodies, full addresses, phone numbers, tokens, private headers, attachments,
or live URLs.

When using the optional Gemini assistant, use independent mode by default:
record the preliminary human label and notes before viewing the suggestion.
Record any changed label and reason. Gemini's `unable_to_determine` suggestion
is not a final benchmark label, and Gemini never counts as the second human
reviewer.
