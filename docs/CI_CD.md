# CI/CD plan

This phase adds no automatic deployment workflow. A protected pipeline should
run, in order:

1. secret scan and generated-file checks;
2. backend tests, compileall, pip check, security tests, provisioning tests,
   registry/hash validation, and Docker build validation;
3. frontend `npm ci`, tests, TypeScript, lint, build, npm audit, and Playwright
   when browser processes are available;
4. `git diff --check` and artifact/registry immutability checks;
5. a protected staging approval before any deployment action.

Production deployment credentials and model URLs must be injected by protected
environment configuration, never committed or passed as Docker build args.
