# Version 1.0.0 evaluation harness

`apps/api/scripts/evaluate_v1.py` is a read-only evaluation and benchmarking
runner for the production `AnalysisPipeline`. It does not fit, calibrate,
activate, threshold, deploy, or modify the model or datasets.

## Ground-truth manifest

Every quality sample must contain these exact fields:

```json
{
  "id": "reviewer-assigned-stable-id",
  "label": "phishing",
  "source": "approved-source-id",
  "campaign": "campaign-group-id",
  "date": "2026-07-29",
  "expected_class": "phishing",
  "category": "Microsoft",
  "raw_email": "From: ..."
}
```

`label` and `expected_class` must both be one of `safe`, `suspicious`, or
`phishing`, and they must agree. `category` is optional at ingestion time, but
category metrics are unavailable unless it is explicitly supplied. The runner
never maps `0/1`, spam/scam names, filenames, sender names, or subject text to a
class or category.

Supported inputs are RFC822 `.eml` files, raw email text, JSON/JSONL fixtures,
CSV rows containing an explicit raw email field, and recursive directories. A
directory can pair a raw `.eml` with a JSON sidecar containing `path` or `file`
plus the required ground-truth fields.

## Run

```powershell
python apps/api/scripts/evaluate_v1.py `
  --dataset path/to/reviewer_manifest.json `
  --performance-dataset path/to/eml-directory `
  --output reports/evaluation
```

The performance dataset is optional and is deliberately separate from quality
evaluation. It can contain unlabeled inputs, but its results are not used in
accuracy, error, category, or calibration metrics. Use `--strict` in CI to
return a nonzero exit code when any record is rejected or no complete labeled
sample is available.

## Reports

The runner writes `reports/evaluation/summary.md`, `metrics.json`,
`confusion_matrix.csv`, `false_positives.csv`, `false_negatives.csv`,
`benchmark.json`, `category_metrics.csv`, `latency.json`,
`recommendations.md`, and `NEXT_IMPROVEMENTS.md`, plus privacy-safe prediction,
true-positive/true-negative, calibration, reliability-diagram, and safety-review
artifacts. Raw bodies, URLs, headers, and attachment contents are not written.

Binary quality metrics treat `phishing` as positive and both `safe` and
`suspicious` as non-phishing. Three-class confusion and per-class metrics are
reported separately. Calibration is measured only; no calibration operation is
performed.

## Phase II gold-standard curation

The production harness is read-only, but a trustworthy benchmark also requires
provenance, privacy, overlap, and manual adjudication controls. The Phase II
curator is documented in [GOLD_STANDARD_DATASET.md](GOLD_STANDARD_DATASET.md),
with its schema at
[`services/ml/evaluation/schema/gold_standard_schema.json`](../services/ml/evaluation/schema/gold_standard_schema.json).
It never infers labels from source annotations or model predictions. Existing
repository datasets remain separate as training-only, diagnostic-only, or
external-validation-only material unless a future review explicitly qualifies
them. With insufficient adjudicated samples, the pilot command writes readiness
and shortfall reports and deliberately withholds headline metrics.

Gemini assistance is audited separately under
`reports/gold_standard/gemini_assistance/`. Agreement with a suggestion is not
phishing accuracy, benchmark accuracy, model accuracy, or ground-truth
correctness.
