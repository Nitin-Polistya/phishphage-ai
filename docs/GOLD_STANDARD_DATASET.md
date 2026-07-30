# Gold-standard evaluation dataset

PhishShield AI separates production evaluation from dataset curation. The
versioned schema is [`services/ml/evaluation/schema/gold_standard_schema.json`](../services/ml/evaluation/schema/gold_standard_schema.json), and the standard-library curator is [`apps/api/scripts/build_gold_standard_dataset.py`](../apps/api/scripts/build_gold_standard_dataset.py).

The current status is: **curation framework complete; more manual review
required**. Existing repository data did not qualify automatically. Source
labels, filenames, weak labels, challenge annotations, and model predictions
are never converted into ground truth.

The optional local Gemini assistant is documented in
[`GEMINI_REVIEW_ASSISTANT.md`](GEMINI_REVIEW_ASSISTANT.md). It produces an
advisory suggestion only; it cannot replace a human label or reviewer two.

Long-term reviewed-sample storage, state transitions, reviewer agreement,
duplicate controls, immutable audit history, dashboard metrics, and approved
privacy-safe exports are documented in
[`GOLD_DATASET_MANAGEMENT.md`](GOLD_DATASET_MANAGEMENT.md).

## Record contract

Every public record contains a deterministic `sample_id`, stable SHA-256
hashes, source identity, campaign/date/language fields, safe sender/URL/
attachment metadata, explicit review state, privacy status, and a
`local-only://` content token. It contains no raw body, full address, phone
number, private header, attachment bytes, token, or full live URL.

`expected_class` is nullable while a record is unreviewed or provisional. Its
only valid non-null values are `safe`, `suspicious`, and `phishing`. A final
independent benchmark record must be adjudicated and pass every automated
quality gate.

## Manual workflow

```powershell
.\apps\api\.venv\Scripts\python.exe apps/api/scripts/build_gold_standard_dataset.py scan `
  --input <private-candidate-directory> `
  --manifest services/ml/evaluation/candidate_manifest.jsonl

# Review services/ml/evaluation/review_queue.csv and fill a separate copy of
# services/ml/evaluation/review_labels_template.csv.
.\apps\api\.venv\Scripts\python.exe apps/api/scripts/build_gold_standard_dataset.py apply-labels `
  --manifest services/ml/evaluation/candidate_manifest.jsonl `
  --labels <private-review-labels.csv>

.\apps\api\.venv\Scripts\python.exe apps/api/scripts/build_gold_standard_dataset.py validate `
  --manifest services/ml/evaluation/candidate_manifest.jsonl

.\apps\api\.venv\Scripts\python.exe apps/api/scripts/build_gold_standard_dataset.py export `
  --manifest services/ml/evaluation/candidate_manifest.jsonl `
  --output services/ml/evaluation/benchmark_manifest.jsonl
```

The first reviewer creates a provisional record. A second independent reviewer
must label it without seeing the first label where practical. Disagreements
require documented adjudication, final reviewer, and date. Only then can a
record enter the independent validation subset. The ignored private location
map is the safe local mechanism for opening content by `sample_id`; it is never
part of the public manifest.

## Explicit subsets

| Subset | Use | Headline metric status |
| --- | --- | --- |
| Development diagnostic | Debugging and regression checks; may contain seen material | Not headline evidence |
| Independent validation | Untouched, privacy-approved, overlap-reviewed, adjudicated records | Headline evidence |
| Challenge | Difficult phishing and hard negatives | Report separately |
| Category stress | Brand, business, newsletter, receipt, alert, shipping, government/legal, education, healthcare, and spam slices | Report separately |

These subsets must not be silently combined. Training/development records are
not independent validation records.

## Quality gates and pilot

A record enters the independent benchmark only when schema validation, known
source, unique ID, content existence, stable hash, privacy pass, exact/near
duplicate review, no training/development overlap, non-empty campaign, explicit
date/language, review notes, two independent labels, complete adjudication, and
no unresolved conflict all pass. `validate --final` enforces these gates.
`export` writes only records that pass them and creates a deterministic lock
report; an empty export is marked `not_ready`.

The minimum pilot target is 100 safe, 50 suspicious, and 100 phishing records;
the recommended initial target is 300/100/300. Until the minimum is met, the
curator writes readiness and shortfall reports and withholds headline metrics.
Once it is met, `pilot` constructs a private local harness manifest and runs
the existing read-only `evaluate_v1.py` harness. No model, threshold,
calibration, rule score, or inference behavior is changed.

## Reports

`python ... build_gold_standard_dataset.py audit` writes privacy-safe evidence
under [`reports/gold_standard/`](../reports/gold_standard/): source inventory,
eligibility decisions, leakage and near-duplicate queues, balance/diversity,
collection targets, scientific validity, privacy findings, portfolio-safe
summary, and pilot readiness. Empty reports are intentional when no qualified
benchmark exists.
