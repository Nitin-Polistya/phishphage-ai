# License gate

Status: **BLOCKED**.

At baseline, the repository tracked a root `LICENSE` file containing MIT text. During this validation pass the working tree now shows that path as deleted and an untracked `LICENSE.md` containing the same text. This local rename state was not assumed to be an approved license decision and was not automatically repaired or deleted.

Required user action:

1. Confirm whether MIT is the intended project license.
2. Resolve the `LICENSE` versus `LICENSE.md` path explicitly.
3. Track the approved root `LICENSE` file and review README/license references.

No license badge was added automatically, no new license was selected, and the release cannot be tagged while the root license path is unresolved.
