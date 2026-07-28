# Rollback strategy

Rollback is a release operation, not a deletion operation. Preserve the last known-good frontend/backend configuration, registry entry, artifact hash, and validation evidence.

## Frontend and backend

Roll back the Next.js and FastAPI releases independently when their contracts remain compatible. Revert provider environment configuration through the provider's versioned mechanism. Do not delete browser data or application data to recover from a release problem.

After rollback, verify the frontend can reach the exact API origin, CORS is correct, `/api/v1/health` and `/ready` are healthy, and synthetic analysis returns the expected contract.

## Model rollback

Select the previous reviewed registry entry and its matching private artifact/vectorizer/manifest hashes. Provision them into a new immutable release. A missing file, hash mismatch, unsupported registry version, invalid threshold/metadata, or failed inference adapter keeps required-ML readiness at HTTP 503. Never overwrite an existing artifact in place.

## Security rollback

For a security regression, restore the last known-good application and configuration release, then rerun security-control, dependency, readiness, and synthetic API gates. If the regression concerns the unauthenticated API, restrict ingress access while the fix is reviewed. Do not claim the browser security gate passed while host-level browser launch remains blocked.

## Firebase and state

Firebase is optional and the repository defines no schema or authorization boundary. Any future Firebase change requires a separate migration/rules rollback plan. Browser-local history can be cleared by the user but is not a server rollback mechanism.
