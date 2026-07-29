# Repository hygiene gate

## Tracked content

The tracked tree contains source, tests, manifests, documentation, synthetic fixtures, registry metadata, and sanitized reports. `git ls-files` shows no tracked model binaries, raw dataset files, `.env` files, virtual environments, `node_modules`, `.next`, browser profiles, or generated local screenshot binaries.

The model registry is tracked, but the registry-selected pipeline, vectorizer, feature manifest, experimental artifacts, and research report directories are ignored and remain local/private.

## Ignored local content

`git status --ignored --short` reports expected local artifacts including virtual environments, `node_modules`, `.next`, TypeScript build info, logs, generated screenshots, Playwright state, cached reports, ML artifacts, and local datasets. These are not release inputs and were not deleted.

The `apps/api/.dockerignore` excludes Python caches, `.env`, virtual environments, tests, data, reports, ML reports/artifacts, and Joblib binaries from the API image context.

## Current worktree exception

Release metadata and documentation changes are intentionally uncommitted for review. The status also shows `LICENSE` deleted and `LICENSE.md` untracked; this is the license-gate blocker described separately. Only the intentionally curated `reports/release_candidate/` package is made visible to Git; unrelated generated reports remain ignored.
