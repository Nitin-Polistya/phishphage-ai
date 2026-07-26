# Model artifact distribution

The registry remains the source of truth for model ID, version, threshold,
calibration, and expected hashes. The approved binary is not tracked in Git or
baked into the public image.

The primary workflow is a private HTTPS release/storage asset exposed to the
deployment command as `MODEL_ARTIFACT_URL`, with an optional secret bearer
token. `provision_model_artifact.py`:

- requires HTTPS and deployment-provided configuration;
- resolves the destination inside `services/ml` only;
- applies a timeout and maximum byte limit;
- writes to a same-directory temporary file;
- fsyncs and verifies SHA-256 before atomic rename;
- refuses to overwrite an existing artifact;
- removes temporary files on every failure;
- never prints URLs, tokens, email content, or credentials.

Run `python apps/api/scripts/provision_model_artifact.py --dry-run` to validate
configuration without a network request. The normal provisioning command is
called only by the deployment container command, not by local application
imports. The registry, vectorizer, and feature manifest must be supplied by the
private deployment bundle or mounted approved model directory and must pass
the existing model-manager integrity checks before deserialization.
