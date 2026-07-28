# Security policy

The detailed security architecture, threat model, residual risks, disclosure guidance, and control assumptions are in [docs/SECURITY.md](docs/SECURITY.md).

## Reporting

Use a private repository security advisory when available. If no private channel exists, open a minimal public issue requesting one; do not include real email content, personal data, credentials, live malicious URLs, attachment files, or exploit payloads. Include only a sanitized reproduction, affected route/component, expected versus observed behavior, and tool versions. Allow maintainers reasonable time to validate and remediate before public disclosure.

## Supported versions

The current repository development line is the only supported line. There is no deployed service or formal long-term support policy.

## Security boundaries

- Raw analysis is intended to remain in memory; the API does not persist raw email or attachment bytes.
- HTML is not rendered, URLs are not followed, and attachments are not executed.
- Browser-local history is optional and stores sanitized summaries only.
- Model artifacts are hash-checked and path-contained, but trusted Joblib/Pickle loading remains an operator trust boundary.
- The model supports human review and does not guarantee phishing detection.
- The deployment candidate is inactive until a separate release decision.
