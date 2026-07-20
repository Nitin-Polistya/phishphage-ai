# Security policy

## Reporting

Please use a private repository security advisory when available. If that is not available, open a minimal issue asking for a private reporting channel; do not include real email content, personal data, credentials, live malicious URLs, or attachment files in public issues.

Include the affected route/component, a sanitized reproduction, expected versus observed behavior, and the environment/tool versions. Allow maintainers reasonable time to validate and remediate before public disclosure.

## Supported versions

The current repository state is the only supported development line. There is no deployed service or formal long-term support policy yet.

## Security boundaries

- Raw analysis is intended to remain in memory and is not persisted by the production analysis workflow.
- Email HTML is not rendered, URLs are not followed, and attachments are not executed.
- The frontend must not log or persist submitted email.
- The model is decision support and does not guarantee phishing detection.
- The deployment candidate is inactive until a separate release decision.

## Safe testing

Use the built-in synthetic `example.com` message or another fully fabricated message. Do not upload real customer, employee, or incident-response email to development environments.
