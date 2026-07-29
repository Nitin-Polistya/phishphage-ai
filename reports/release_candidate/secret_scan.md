# Secret scan

Status: **No high-confidence committed secret found; external scanner limitation remains.**

## Local scan scope

- Tracked source, tests, manifests, docs, examples, and release-facing reports.
- Patterns for PEM private keys, GitHub tokens, OpenAI-style keys, AWS access keys, bearer authorization headers, password assignments, Firebase private keys, and common personal mailbox domains.
- Git history pattern checks were limited to safe pattern names and redacted path/count output; secret values were not printed.

## Findings

- PEM/private-key pattern: 0.
- GitHub token patterns: 0.
- AWS access-key pattern: 0.
- Authorization bearer header pattern: 0.
- Personal Gmail/Yahoo/Outlook/Hotmail address pattern: 0.
- `sk-` matches were benign source/package text false positives, not credential-shaped values.
- Password pattern matched a frontend field name only; no literal password value was found.
- Empty secret placeholders in `.env.example` files and test strings such as `not-a-real-key` are intentional fixtures/documentation.

No secret values are reproduced in this report. A dedicated external secret-scanning service was not available, so this is a conservative local scan rather than proof of absence from every historical object or provider cache.
