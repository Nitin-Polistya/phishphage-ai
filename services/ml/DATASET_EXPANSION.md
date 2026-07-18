# Phase B Dataset Expansion Framework

This phase audits and plans English corpus expansion. It does not download data, create synthetic messages, retrain the model, or alter an evaluation boundary.

## Current boundary model

- `data/processed/english_core_v3.csv` is the active 298-row development pool (193 legitimate, 105 phishing). It is used for grouped out-of-fold development and the final model fit; it is not a fixed train/validation/test export.
- `data/processed/grouped_template_diagnostic_v2.csv` is a 178-row selection-aware robustness diagnostic, not an untouched test.
- `data/external/development_benchmark.csv` is a 100-row previously inspected development benchmark.
- `data/external/final_external_benchmark.csv` is the 80-row post-lock final benchmark used by Step 3.
- The untouched Zenodo publisher download and its derivatives remain physically under `data/external/` and are forbidden as training inputs.

The v3 development pool has 271 campaign groups. Its 66 synthetic rows are 22.15% of development data. The Zenodo social-engineering source contributes 232/298 rows (77.85%), including 83/105 phishing rows and 149/193 legitimate rows. This is a material source imbalance even though canonical and close SimHash duplicates were removed during Step 3.

## Standard provenance

`config/dataset_provenance_schema.json` defines the record contract. Required fields include stable IDs, label, source and license references, acquisition date, language, synthetic flags, campaign/template/message-type grouping, split role, external-only status, URL/attachment availability, and irreversible content hashes. Brand, delivery provider, organizational sender domain, and notes are optional because many sources cannot provide them safely or reliably.

For newly approved records, `sample_id`, `label`, `source_name`, `language`, both synthetic flags, `campaign_group`, `template_group`, `message_type`, `split`, `external_evaluation_only`, and both hashes must have non-null values. Source record ID, source/license references, acquisition date, URL presence, and attachment presence are mandatory schema keys; legacy rows may temporarily hold null only so the inventory can measure the backfill deficit. Brand family, delivery provider, organizational sender domain, and notes are optional keys.

Missing values stay missing; they are not inferred from filenames or guessed from message vocabulary. Provenance exports must not contain message bodies, private recipient addresses, sender local-parts, unnecessary names, live tokens, or attachment content. Notes must never copy raw message content.

## Source approval gate

A reviewer must complete a copy of `config/dataset_source_manifest.example.json` before ingestion:

1. Verify the publisher-controlled homepage and direct acquisition method.
2. Record the license text/reference and confirm the intended processing and deployment uses. `unknown` always means `manual_review_required`, `enabled: false`.
3. Review the original labels. Generic spam is not phishing, and URL reputation records are not email-body labels.
4. Confirm English scope, privacy handling, permitted splits, expected taxonomy categories, and mandatory provenance.
5. Record a publisher checksum when available and verify it before parsing.
6. Approve campaign/template grouping and exact, normalized, and semantic deduplication policies.
7. For external-only data, set `external_evaluation_only: true` and allow only `external`.

Authentication requirements, unavailable downloads, ambiguous labels, unclear licensing, or incompatible privacy terms block the source. Do not bypass restrictions. The current `dataset_sources.json` records Enron and SpamAssassin as blocked, SpaPhish as blocked/excluded from the English model, Zenodo validation as external-only, and PhishTank/OpenPhish as URL-only. The locally documented contextual CC0 benchmark does not yet have a corresponding entry in that registry and requires provenance-record reconciliation before reuse in any future dataset operation.

## Taxonomy and acquisition planning

`config/dataset_expansion_taxonomy.json` covers legitimate hard negatives and phishing campaign families. Brand categories are audit labels only; they must not become explicit model features. Targets are long-term diversity goals, not quotas and not permission to manufacture examples.

The planner credits only the active development pool. Diagnostics and external benchmarks do not count toward training coverage. It ranks real-sample, campaign, and source deficits, then recommends small independently licensed batches. A larger corpus is not necessarily a better corpus.

Long-term planning ranges are 3,000-5,000 legitimate English emails and 2,000-3,000 phishing emails, with multiple independently sourced campaigns per important category, no class dominated by one source, and a low explicitly reported synthetic contribution.

## Split and leakage policy

- Campaigns, templates, exact duplicates, normalized duplicates, and semantic near-duplicates must remain in one train/validation/test group.
- Source-balanced, campaign-grouped splitting is required; test campaigns must be independently sourced.
- External data never enters model fitting, feature/candidate selection, calibration, or threshold selection.
- Zenodo Phishing Validation Emails remain external-only.
- Generic spam remains an unlabeled hard-negative pool unless a separate reviewed task defines an appropriate use; it is never automatically phishing.
- PhishTank/OpenPhish remain URL reputation inputs, not message labels.
- Spanish rows are excluded from the primary English model.
- Synthetic rows must not dominate a split or taxonomy category. The validator warns above 40% synthetic contribution and above 50% contribution from one source.

`validate_corpus_boundaries` fails on cross-split exact, normalized, campaign, or template overlap; external rows in training boundaries; Spanish rows in the primary English boundaries; generic SpamAssassin spam labeled phishing; and missing campaign groups in fixed train/validation/test splits. Near duplicates are detected with the existing canonicalization and 64-bit tri-shingle SimHash policy and must be assigned a common group before splitting.

## Commands

Run from `services/ml` with its environment active:

```powershell
python scripts/audit_corpus_inventory.py
python scripts/analyze_dataset_gaps.py
pytest tests/ -v
python -m compileall src scripts tests
```

Generated reports are Git-ignored:

- `reports/corpus_inventory.json`
- `reports/corpus_inventory.md`
- `reports/dataset_gap_analysis.json`
- `reports/dataset_gap_analysis.md`

The inventory is read-only and contains aggregate metadata and hashes, never message content.

## Controlled acquisition lifecycle

Future sources must use `config/dataset_source_registry.json`. Registry entries carry explicit approval, license, privacy, language, label, split, format, deduplication, and campaign policies. The only statuses are `approved`, `blocked`, `pending`, and `external_only`. Unknown licensing remains `pending`; an ingestion-enabled entry must have approved source, license, and privacy status and must not be external-only.

No acquisition file enters `processed/` directly. The enforced lifecycle is:

```text
Source registry -> license validation -> privacy validation -> normalization
-> duplicate and overlap detection -> campaign/template validation
-> manual review -> dry-run promotion -> confirmed promotion
```

Each ignored batch lives at `data/staging/<batch_id>/`:

```text
manifest.json
raw/
normalized/
validation/
reports/
```

`ingest_batch.py` has no network capability. It reads only the exact CSV or JSONL placed under that batch's `raw/` directory. It validates the controlled registry and taxonomy, rejects forbidden private structured fields, normalizes text, calculates SHA-256 content and canonical hashes plus 64-bit SimHash, and checks exact, normalized, near-duplicate, campaign, and template overlap against development and external boundaries. Rejection reports contain identifiers and reasons, never rejected message content or private values.

The review queue records `review_status`, reviewer, UTC review time, notes, approved label/category/campaign/template, and explicit privacy/license checks. Allowed decisions are `approve`, `reject`, `needs_revision`, and `external_only`. Approval requires a named reviewer, both checks, and complete approved metadata.

Promotion always begins with `--dry-run`. The preview reports approved/rejected/duplicate rows, class, source, campaign and taxonomy balance, synthetic percentage, new campaigns, warnings, and blockers. `--confirm` is a separate explicit operation and fails if any normalized row is unapproved, any ingestion rejection or duplicate remains, any review check is incomplete, or a fresh overlap check fails. Destinations are restricted to CSV files under `data/processed/`.

### Example workflow

```powershell
python scripts/ingest_batch.py init `
  --batch-id 2026-07-reviewed-source-001 `
  --source-id zenodo_phishing_nlp_15235123 `
  --input-filename reviewed.jsonl `
  --acquisition-date 2026-07-18

# Place the already acquired and reviewed file at:
# data/staging/2026-07-reviewed-source-001/raw/reviewed.jsonl

python scripts/ingest_batch.py run --batch-id 2026-07-reviewed-source-001

python scripts/review_batch.py `
  --batch-id 2026-07-reviewed-source-001 `
  --sample-id SOURCE:SAMPLE `
  --status approve `
  --reviewer REVIEWER_ID `
  --privacy-checked `
  --license-checked

python scripts/promote_batch.py `
  --batch-id 2026-07-reviewed-source-001 `
  --dry-run

# Only after independent review of every generated report:
python scripts/promote_batch.py `
  --batch-id 2026-07-reviewed-source-001 `
  --confirm
```

This documentation is illustrative; no batch was initialized, ingested, reviewed, or promoted by the Phase B implementation task.

### Reports and rollback

Every ingestion writes `batch_validation.json`, `batch_validation.md`, `rejected_rows.json`, `duplicate_report.json`, the normalized JSONL, and the review queue. Every dry run writes `promotion_preview.json` and `promotion_preview.md`. Confirmed promotion also writes a receipt with destination hashes and, when the destination existed, `promotion_backup.csv` inside the ignored batch reports directory.

Rollback is a controlled manual recovery operation: stop further promotions, verify the receipt's pre/post hashes, copy the recorded backup over the exact receipt destination, rerun the corpus inventory and leakage audit, and record the incident outside message content. If no backup exists, the receipt represents creation of a new destination and rollback means removing that exact created file only after independent authorization. The promotion command never performs automatic rollback and never overwrites a path outside `data/processed/`.
