# Contributing to PhishPhage AI

PhishPhage AI is a defensive cybersecurity project. Contributions should improve analysis, explainability, safety, privacy, or documentation without turning the system into an automated guarantee.

## Community expectations

Be respectful, specific, and patient. Assume good intent, explain security-sensitive tradeoffs, and avoid publishing private data or operational details that could harm others. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Setup

Follow [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Use the repository's Python and Node manifests, synthetic `example.com` inputs, and ignored local environment files.

## Branches and commits

Use focused branches such as `docs/api-contract`, `fix/parser-boundary`, or `test/model-adapter`. Keep commits small and imperative, for example `Document model artifact governance`. Do not commit automatically from tooling or include unrelated local changes.

## Testing and formatting

Run the relevant backend pytest/compile/pip checks and frontend test/TypeScript/lint/build checks. Run `git diff --check`. There is no checked-in Black command; if you use a local formatter, review the diff and keep formatting-only changes scoped.

## Security-sensitive contributions

- Do not weaken CORS, CSP, request limits, rate limits, safe errors, path containment, or hash verification to make a test pass.
- Do not add URL fetching, HTML rendering, attachment execution, or implicit trust of authentication headers without a separate security design review.
- Do not add authentication claims unless the implementation and deployment boundary support them.
- Include synthetic regression coverage and document residual risk.

## Dataset contributions

- No raw personal emails, credentials, active malicious URLs, attachment bytes, or copied mailbox content.
- Provide source, license, privacy, label, language, campaign, template, and split provenance.
- Preserve exact/normalized/semantic deduplication and campaign grouping.
- Keep generic spam separate from phishing.
- Do not promote blocked, pending, external-only, or privacy-unreviewed data.

## Model artifacts

Do not commit model binaries, private artifact URLs, secrets, unverified registry entries, or experimental artifacts as if they were approved. Every model change needs reproducible evaluation, calibration/threshold evidence, hash metadata, adapter tests, and an explicit governance decision. An experimental SVM or hybrid feature result must not be documented as the runtime model.

## Pull request checklist

- [ ] Scope and user-facing impact are explained.
- [ ] Relevant tests and exact commands are recorded.
- [ ] Documentation and links are updated.
- [ ] No raw personal email, secrets, private URLs, or absolute local paths were added.
- [ ] API contracts, thresholds, calibration, and inference behavior are unchanged unless explicitly approved.
- [ ] Security-sensitive changes include threat-model and regression coverage.
- [ ] Dataset changes include licensing/privacy/provenance evidence and do not silently relabel spam.
- [ ] Model changes distinguish experimental, deployment-candidate, activated, and rejected states.
- [ ] Generated reports are sanitized and placed under the appropriate reports directory.
- [ ] `git diff --check` passes.

## Documentation expectations

Document what the repository proves, distinguish local validation from deployment, disclose known limitations, and avoid accuracy or safety guarantees. Use the canonical public name PhishPhage AI in new public documentation; preserve internal names when changing them would be an unrelated compatibility change.
