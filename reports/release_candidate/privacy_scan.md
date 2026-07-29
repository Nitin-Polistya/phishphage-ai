# Privacy scan

Status: **Pass for tracked release-facing content, with normal authorized-input limitations.**

- New portfolio fixtures use reserved `example.com`, `example.org`, and `example.net` domains, fabricated names, and inert URLs.
- No raw mailbox export, attachment bytes, authentication token, Firebase credential, private model URL, browser profile, or local absolute path was added.
- Existing tracked fixtures and docs were reviewed as sanitized/synthetic by the prior security and documentation audits.
- Public copy describes browser-local history as opt-in and sanitized; it does not claim that arbitrary user environments are safe for sensitive mail.
- The remote repository slug still contains the historical `phishphage` name and internal compatibility identifiers remain; these are naming/identity concerns, not personal data.
- Ignored generated screenshots and logs were not added to the release tree.

Manual browser QA and screenshot review remain required before publishing any binary portfolio asset. Use [`docs/PORTFOLIO_ASSET_CHECKLIST.md`](../../docs/PORTFOLIO_ASSET_CHECKLIST.md).
