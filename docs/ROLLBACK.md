# Rollback strategy

Frontend and backend releases roll back independently to the last known-good
release. Environment changes are reverted through the hosting provider's
versioned configuration, never by deleting application data.

Model rollback selects the previous approved registry entry and its preserved
SHA-256, then provisions that artifact into a new immutable release. A failed
provision, hash mismatch, unsupported registry version, or missing artifact
keeps the service from becoming ready when `ML_REQUIRED=true`.

Security regressions require restoring the last known-good frontend/backend
release and configuration, then rerunning the security and deployment gates.
Firebase changes, if introduced later, require a separately reviewed backward-
compatible migration and rules rollback; this phase makes no Firebase schema
or data changes.
