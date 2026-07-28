# Model artifact distribution

Model binaries are release inputs, not public Git assets. The tracked registry remains the source of truth for model ID, version, calibration, threshold, activation state, compatibility, and hashes. The current record is a deployment candidate and is not activated.

## Required release bundle

A deployment bundle must contain the registry-compatible:

- fitted pipeline artifact;
- vectorizer artifact;
- feature manifest;
- registry metadata and release-specific hash record.

The paths must remain inside the approved model directory. Do not copy raw datasets or research artifacts into the public frontend image.

## Provisioning behavior

The provisioning script is intended for an operator-controlled private HTTPS source. It:

1. requires deployment configuration;
2. rejects non-HTTPS sources;
3. enforces a timeout and maximum byte count;
4. resolves the destination inside the approved model directory;
5. writes to a same-directory temporary file;
6. fsyncs and computes SHA-256 before installation;
7. refuses to overwrite an existing artifact;
8. removes temporary files after failures;
9. never logs source URLs, bearer tokens, email content, or credentials.

Use the dry run to validate local configuration without downloading:

```powershell
.\apps\api\.venv\Scripts\python.exe apps\api\scripts\provision_model_artifact.py --dry-run
```

The Docker command calls provisioning before Uvicorn starts. Local application imports do not download artifacts. After provisioning, `ModelManager` rechecks pipeline, vectorizer, and feature-manifest hashes and bundle metadata before Joblib deserialization.

## Failure and rollback

Missing configuration, invalid URL scheme, size/timeout failure, path escape, existing destination, hash mismatch, invalid registry metadata, or incompatible model state fails closed. With `ML_REQUIRED=true`, readiness remains unavailable. Roll back by selecting the previous reviewed registry entry and provisioning its matching immutable artifact; do not overwrite an artifact in place.

## Privacy and repository rules

Never publish private artifact URLs, tokens, raw email, serialized model contents, or local absolute paths. Model and dataset binaries are ignored by Git. Registry metadata and sanitized aggregate reports may be reviewed in source control, but their presence does not make a model production-approved.
