# Backend validation gate

Status: **Pass.**

- Command: `apps/api/.venv/Scripts/python.exe -m pytest -q apps/api/tests`
- Result: **245 passed, 2 warnings in 71.72s**.
- Warnings: known Starlette/httpx and httpx raw-content deprecation warnings; no correctness or security failure indicated.
- Command: `apps/api/.venv/Scripts/python.exe -m compileall apps/api/app apps/api/scripts services/ml/src`
- Result: pass.
- Command: `apps/api/.venv/Scripts/python.exe -m pip check`
- Result: `No broken requirements found.`
- Formatter/linter: no checked-in Python formatter or linter command is configured; no dependency was added during the freeze.

The full suite covers parser, input modes, rules, decision safety, model adapter/integrity, deployment configuration, observability, performance tooling, and security controls.
