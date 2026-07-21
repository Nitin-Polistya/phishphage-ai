# Approved model artifact distribution

The tracked source of truth is `services/ml/models/registry.json`. The selected
entry is `phase-c-logistic-regression-v1`, with deployment candidate state true,
activation state false, threshold `0.5`, and the SHA-256 recorded in the registry.

The binary is intentionally excluded from Git. Production provisioning must
retrieve the exact approved artifact from a private release attachment or
provider-managed private/persistent storage, then place it at the registry
relative path (or set `ML_ARTIFACT_PATH`). Do not choose a public host or commit
the binary without an explicit repository policy decision.

Before the API loads it, `ModelManager` resolves paths from the repository root,
computes SHA-256, compares it with both registry hash fields, validates the
registry metadata, and verifies the serialized model ID, inactive state, and
threshold. A missing or mismatched artifact is never loaded.

## Fresh-clone verification

From a fresh clone:

1. Install `apps/api/requirements.txt`.
2. Retrieve the private approved artifact through the release process and place
   the three registry-referenced files under `services/ml/artifacts/...`, or
   configure `ML_ARTIFACT_PATH` for the pipeline artifact.
3. Set `ML_REGISTRY_PATH`, `ML_MODEL_ID`, and `ML_REQUIRED=true`.
4. Start Uvicorn from either the repository root or `apps/api`.
5. Check `GET /api/v1/health`; it must return readiness, hash verification, the
   model ID, version, and deployment-candidate state without filesystem paths.
6. Send one synthetic RFC822 message to `POST /api/v1/analyze` and verify the
   returned model ID, version, threshold, and processing time.
7. Remove the provisioned artifact and repeat the health check; readiness must
   fail safely with HTTP 503 and no path or traceback leakage.

For local development, leave `ML_REQUIRED=false` to keep the rule-based
analysis available while reporting ML as unavailable.
