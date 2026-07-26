# Model artifact security

Only registry-selected local artifacts under the approved `services/ml` tree are eligible. Resolved paths are contained against traversal and symlink escape, registry SHA-256 values are checked before `joblib.load`, vectorizer and feature-manifest hashes are checked, and loaded metadata must match model ID, inactive activation state, and existing threshold metadata. User input cannot select an arbitrary path or artifact ID through an API route.

Residual risk: Joblib/Pickle deserialization can execute code by design. Hash verification provides integrity, not inherent safety; only trusted internally produced artifacts and controlled distribution may be used.
