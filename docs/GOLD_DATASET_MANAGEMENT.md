# Phase III gold dataset management

Phase III extends only the local Dataset Review boundary. It does not retrain,
activate, calibrate, threshold, register, or alter any production model. The
`/analyze` route, feature engineering, existing analyzer, and deployment
configuration are unchanged.

## Architecture

The manager uses the ignored local SQLite file configured by
`DATASET_REVIEW_STORAGE_PATH` (default:
`services/ml/evaluation/private/review_workspace.sqlite3`). Phase III adds
`gold_reviews`, `gold_reviewer_decisions`, `gold_reviewer_agreement`, and
`gold_review_audit` tables beside the existing sanitized Dataset Review tables.
Relative storage paths resolve from the repository root, independently of the
API process working directory. The configured SQLite path and all generated
exports/reports must remain under the ignored
`services/ml/evaluation/private/` directory; paths outside it and traversal
paths are rejected.
The audit table has database triggers that reject update and delete attempts.

```text
sanitized Dataset Review evidence
              |
              v
     GoldDatasetManager (SQLite)
       |       |        |
       |       |        +--> immutable audit trail
       |       +-----------> reviewer decisions --> agreement/kappa
       +-------------------> state machine --> approved-only exports
                                      |
                                      +--> dashboard metrics and reports
```

Human reviewers remain the only authority. Gemini recommendation and reasoning
are stored as advisory provenance only. `accepted_gemini_recommendation` is a
human-recorded fact; it never maps a suggestion into a final label.

## Review states

The valid workflow is:

```text
Pending -> Reviewed -> Needs Second Review -> Approved -> Archived
   |          |              |                  |
   +------> Rejected --------+------------------+
```

Invalid transitions are rejected. Approval requires a determinate human label;
samples marked for second review require two human decisions with no conflict.
Rejected and approved samples can only move to Archived. Approved and archived
records are immutable; a materially different source/version must be curated as
a separate review identity rather than silently changing an approved record.

## Duplicate and agreement controls

Creation rejects an existing `sample_hash`, `normalized_content_hash`, or the
same campaign/source identity. Reviewer decisions are unique per sample and
reviewer. Paired decisions calculate agreement rate, disagreement count,
Cohen's kappa, per-reviewer consistency, and label-pair conflict statistics.
Statistics are persisted with a computation timestamp and version.

## Privacy-safe exports

`export_gold_dataset()` and the Dataset Review `POST /export` endpoint write to
the ignored local storage directory
`services/ml/evaluation/private/gold_dataset_reports/`:

- `gold_dataset_v1.jsonl`
- `gold_dataset_summary.json`
- `gold_dataset_statistics.md`
- `review_statistics.json`
- `agreement_report.md`
- `quality_metrics.json`
- `label_distribution.csv`
- `gold_dataset_summary.md`

The endpoint verifies that every listed artifact exists as a regular file
under the private root before returning success. It returns the repository-
relative logical output location, ISO-8601 export timestamp, filenames, byte
sizes, and an `all_files_written` flag. Absolute filesystem paths are never
returned to the API client or browser.

Only approved human-reviewed metadata is exported. Source sample IDs are
digested, notes are redacted, and reviewer identity/Gemini reasoning are not
exported. Raw bodies, headers, attachment content, URLs, email addresses,
Message-ID, paths, and PII are excluded.

## API and dashboard

The local admin-token boundary remains in force. Phase III routes are under
`/api/v1/dataset-review/gold-dataset`:

- `GET /dashboard`
- `GET /agreement`
- `GET /reviews`
- `POST /reviews`
- `GET /reviews/{review_id}`
- `POST /reviews/{review_id}/decisions`
- `POST /reviews/{review_id}/transition`
- `POST /reviews/{review_id}/revise`
- `GET /reviews/{review_id}/audit`
- `POST /export`

The Dataset Review page exposes completion, approved count, queue size, second
review count, agreement, label/language/source distributions, and confidence
bins. Metrics require an authorized local session and are not persisted in
browser storage.

## Validation and manual setup

All Phase III provider behavior remains mocked in automated tests. No live
Gemini request is needed for gold-dataset management. Run the normal backend
pytest/compileall checks and the frontend TypeScript, ESLint, and build checks.
The existing Google Gen AI installation and Phase II configuration are the only
manual prerequisites for the optional advisory path; gold-dataset storage and
exports work locally without retraining or model changes.

For a local session, set `DATASET_REVIEW_ENABLED=true`, keep
`DATASET_REVIEW_LOCAL_ONLY=true`, and provide a separate
`DATASET_REVIEW_ADMIN_TOKEN` through the existing ignored environment file.
Start the existing API and web applications, open `/dataset-review`, enter the
token in the in-memory form, and complete the human review fields. The SQLite
workspace and exports are created on demand under ignored private paths. Never
commit the environment file, token, provider key, raw email, or generated
evaluation artifacts.
