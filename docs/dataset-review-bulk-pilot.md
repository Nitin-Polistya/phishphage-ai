# Phase III.B bulk review pilot

This is a local-only human review procedure. Keep `DATASET_REVIEW_ENABLED=true`
only on the local API, set a dedicated `DATASET_REVIEW_ADMIN_TOKEN`, and keep
`GEMINI_REVIEW_ENABLED=false` unless a reviewer explicitly needs one sanitized
advisory suggestion per sample. The source label is provenance, never ground
truth.

## Batch format

Use CSV or JSONL with `source_sample_id` and privacy-safe metadata. Optional
fields include `source_dataset`, `campaign_id`, `language`,
`source_claimed_label`, `subject`, `body_excerpt`, sender/reply-to domains,
authentication summary, URL domains/structural flags, attachment metadata,
`normalized_content_hash`, and `sample_hash`. Do not provide raw `.eml`, raw
headers, complete email addresses, complete URLs, query strings, attachment
contents, or local paths.

The default import limit is 100 rows and the default bulk-operation limit is
100 items. These limits can be raised only within the configured safe maximum.

## Safe 50 + 50 procedure

For Batch A, import 50 legitimate candidates with `source_claimed_label=safe`.
Filter duplicate/error rows, inspect the sanitized previews, select only rows
the reviewer verifies, confirm “Mark Safe”, set confidence, and explicitly
approve eligible rows. Export and inspect the private result.

For Batch B, repeat with 50 phishing candidates and
`source_claimed_label=phishing`. Require a second human review wherever the
evidence is uncertain. Approval remains blocked until the second decision is
complete and any disagreement is resolved.

Do not assume all 100 rows should be labeled or approved. A duplicate, low
confidence, unresolved, or otherwise ineligible row should remain in the
queue, be rejected, or be archived according to the reviewer’s decision.

Every bulk mutation asks for confirmation, records one immutable audit row per
affected review, and returns only privacy-safe identifiers and metadata.
