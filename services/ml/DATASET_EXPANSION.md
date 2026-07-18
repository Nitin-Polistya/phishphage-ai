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
