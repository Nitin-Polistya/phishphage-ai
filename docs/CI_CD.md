# CI/CD plan

No automatic deployment workflow is present or enabled. `render.yaml` and `vercel.json` are provider configuration files with deployment disabled. A future protected pipeline should keep documentation/research changes separate from model and deployment promotion.

## Suggested gate order

1. Secret, raw-email, absolute-path, generated-file, and registry-immutability scans.
2. Backend unit/security/model-adapter/deployment tests, `compileall`, `pip check`, and provisioning dry-run tests.
3. Frontend `npm ci`, tests, TypeScript, lint, build, and `npm audit`.
4. Documentation link/anchor, terminology, version, and Markdown checks.
5. Container build and provider-like startup with a private reviewed artifact.
6. Synthetic health/readiness/API smoke tests and capacity/resource checks.
7. Browser security/visual tests when the host permits browser child processes.
8. Protected staging approval before any deployment action.

## Secret and artifact rules

Production credentials, private artifact sources/tokens, and expected hashes must come from protected environment configuration. Never pass secrets as Docker build arguments, commit them, print them in logs, or include them in reports. Only a registry-compatible, hash-verified artifact may reach a deployment candidate release.

## Current limitations

There is no checked-in automatic deployment workflow. The recorded evidence notes unavailable Docker execution, a stalled post-change frontend npm gate, unverified provider capacity, and browser launch blocked by `spawn EPERM`. These are open validation prerequisites, not reasons to loosen security or model controls.
