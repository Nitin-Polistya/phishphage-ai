# Dependency audit

`npm audit --audit-level=moderate` completed with 0 vulnerabilities across 444 installed packages (49 production, 360 development, 64 optional). No Node dependency upgrades were made.

`pip check` completed successfully: no broken requirements. `pip-audit` was not installed in the API virtual environment, so a Python CVE audit was not claimed. Python dependency versions are inventoried in `apps/api/requirements.txt`; review with `pip-audit -r apps/api/requirements.txt` in the release environment before deployment.

No vulnerability was claimed as fixed through a dependency change.
