# PhishPhage English-First Academic Baseline

This package trains the local text model consumed by the existing API pipeline. It is an academic baseline, not production-grade phishing protection.

## Dataset acquisition review gate

The reproducible acquisition pipeline is documented in [DATASET_ACQUISITION.md](DATASET_ACQUISITION.md). Its reviewed source registry is `dataset_sources.json`. It downloads only exact, HTTPS URLs whose official record states a reusable license and whose label meaning is suitable for the assigned role.

As of the 2026-07-17 audit, only the two Zenodo sources are enabled. CMU Enron is blocked because its official distribution page does not state a reusable content license and asks researchers to handle the real messages sensitively. Apache SpamAssassin is blocked because its official README says copyright remains with the original message senders. SpaPhish remains optional and blocked until a stable unauthenticated official direct download is verified. PhishTank/OpenPhish are excluded because URL reputation is not an email-body label.

Run acquisition and corpus auditing as a separate review phase. Do **not** run `train_model.py` until `preparation_audit.json`, `language_audit.json`, and `deduplication_and_split_audit.json` have been reviewed and an adequately licensed legitimate English source has been approved. The scripts always report `ready_for_training: false`; they do not invoke training.

## Phase B corpus expansion audit

The pre-acquisition framework is documented in [DATASET_EXPANSION.md](DATASET_EXPANSION.md). It adds a privacy-preserving provenance schema, an expansion taxonomy, a disabled source-manifest template, strict boundary validation, and deterministic corpus/gap reports. It does not download data or retrain the current model.

The active v3 development pool contains 298 English rows: 193 legitimate and 105 phishing, across 271 campaign groups. It contains 232 real/curated rows and 66 synthetic rows (22.15%). One Zenodo source contributes 232 rows (77.85%), so source diversity—not raw volume—is the immediate constraint. The 178-row grouped diagnostic remains selection-aware, while the 100-row development benchmark and 80-row final benchmark remain external evaluation boundaries.

Run from `services/ml`:

```powershell
python scripts/audit_corpus_inventory.py
python scripts/analyze_dataset_gaps.py
```

The generated `reports/corpus_inventory.{json,md}` and `reports/dataset_gap_analysis.{json,md}` files are Git-ignored. They report labels, languages, real/synthetic contribution, sources, campaigns, provenance gaps, duplicate controls, split ratios, overlap checks, taxonomy deficits, and dominance warnings without exporting message content. Corpus size alone does not prove quality; every addition still requires verified licensing, privacy review, independent campaign grouping, source diversity, and external-evaluation isolation.

Future acquisition is controlled by `config/dataset_source_registry.json` and the ignored `data/staging/<batch_id>/` workflow. Use `scripts/ingest_batch.py` to initialize and validate a local batch, `scripts/review_batch.py` for explicit human decisions, and `scripts/promote_batch.py --dry-run` before any separately confirmed promotion. Blocked, pending, external-only, privacy-unapproved, license-unapproved, duplicated, ungrouped, unsupported, or incompletely reviewed rows cannot promote. Full lifecycle, report, confirmation, and rollback procedures are in [DATASET_EXPANSION.md](DATASET_EXPANSION.md).

Phase B.2A adds `config/source_review_checklist.json`, the planning-only `config/acquisition_batches/batch_001.json`, `scripts/audit_source_registry.py`, and `scripts/validate_batch_readiness.py`. Batch 001 plans 120 real English messages (70 legitimate, 50 phishing), zero synthetic and zero additional dominant-Zenodo rows. It remains blocked until at least two independent sources have verified license/privacy/acquisition evidence and human approval.

`github_rf_peixoto_phishing_pot` is recorded as a pending, phishing-only candidate for 22 Batch 001 rows. Its CC BY-NC 4.0 license state is `verified_restricted_noncommercial`, not approved; privacy is `pending_sample_review`. `staging_allowed: true` supports only a future separately authorized, ignored staging review, while `development_allowed`, raw storage, ingestion, and redistribution remain false. The planning-only pilot specification and empty report schemas are under `config/acquisition_batches/phishing_pot_pilot_001.json` and `config/report_templates/phishing_pot_pilot/`; the [source-review packet](config/report_templates/phishing_pot_pilot/source_review_packet.md) is the mandatory manual checklist. No staged row may promote until privacy, language, phishing-label, encoded-content, attachment, attribution, duplicate/overlap, campaign/template, source-approval, and explicit development-capability checks all pass. CC BY-NC material remains restricted to non-commercial research; retain attribution and third-party-rights evidence and never redistribute raw emails.

## Step 3: template-shift generalization

Step 3 operates on the already provisioned v2 academic corpus; it does not override the acquisition review gate for future source additions. The existing 178-row grouped diagnostic is reproduced before cleaning. Development data excludes its exact text, removes 428 canonical-template duplicates and 5 close semantic duplicates, removes 2 non-English rows, and reduces synthetic contribution from 68.5% to 22.15%.

Six fixed-threshold candidates were compared: feature sets A (word TF-IDF), B (word + character TF-IDF), and C (word + character TF-IDF + text-derived security indicators), each with balanced Logistic Regression and calibrated LinearSVC. Structured indicators include URL, shortened-domain, punycode, suspicious-TLD, sender/Reply-To, sender/link, visible-link/target, urgency, credential-language, HTML, and attachment signals. They are extracted locally and do not contact URLs or domains.

The selected `ml-english-template-robust-v3.0.0` model is word TF-IDF (1,2) + balanced Logistic Regression with seed 42 and a fixed threshold of 0.50. Candidates had to achieve grouped OOF validation F1 >= 0.85; the fixed grouped diagnostic was then used transparently as a Step 3 development robustness benchmark. Its after-result is selection-aware, not untouched. The 80-row external benchmark was evaluated once after model lock.

| Evaluation | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR | Matrix |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Grouped before | 0.5674 | 0.5283 | 0.6747 | 0.5926 | 0.7973 | 0.8269 | 0.5263 | 0.3253 | `[[45,50],[27,56]]` |
| Grouped after | 0.8483 | 1.0000 | 0.6747 | 0.8058 | 0.7542 | 0.8434 | 0.0000 | 0.3253 | `[[95,0],[27,56]]` |
| External before | 0.9125 | 0.8837 | 0.9500 | 0.9157 | 0.9831 | 0.9829 | 0.1250 | 0.0500 | `[[35,5],[2,38]]` |
| External after | 0.9000 | 1.0000 | 0.8000 | 0.8889 | 0.9944 | 0.9941 | 0.0000 | 0.2000 | `[[40,0],[8,32]]` |

Grouped robustness improved substantially and external accuracy declined by 1.25 percentage points. The external recall loss from 95% to 80% is material: the model is more conservative and still misses unfamiliar phishing messages. Richer features did not win because most corpus rows contain body text rather than complete RFC822/HTML/header context. See generated `reports/generalization_diagnosis.md`, `model_comparison.json`, `corpus_diversity_v3.json`, and `feature_importance.json` for details.

Reproduce Step 3 only after the v2 baseline corpus and benchmark files exist:

```powershell
python services/ml/scripts/improve_generalization.py
python services/ml/scripts/evaluate_model.py `
  --dataset services/ml/data/external/final_external_benchmark.csv `
  --model services/ml/models/phishshield_model.joblib `
  --output services/ml/reports/external_evaluation_v3.json
python services/ml/scripts/finalize_generalization_report.py
```

## Legitimate HTML hard-negative regression

Five synthetic, privacy-safe `.eml` fixtures cover a HubSpot-style newsletter, GitHub Education approval, Gmail welcome message, Mandrill-style OpenAI subscription notice, and MoEngage-style Unstop promotion. They preserve representative MIME/header/HTML structure but contain no personal identifiers or usable provider tokens. They are regression-only inputs under `apps/api/tests/fixtures/legitimate_regression/` and are never read by training.

The rules engine is `rules-v3.1.0`; the unchanged provisioned model is `ml-english-template-robust-v3.0.0` at threshold `0.50`. The follow-up regression replaces the authenticated Gmail case in the five-email acceptance set with a distinct transport-complete fixture that intentionally omits `Authentication-Results`. Before this follow-up, final results were 4 Safe / 1 Suspicious / 0 Phishing. After the configurable marginal-alert rule, the real API result is 5 Safe / 0 Suspicious / 0 Phishing. The missing-authentication Gmail fixture retains its model-only probability (0.569407 in the sanitized fixture), rule/ML disagreement, score-5 missing-authentication finding, reduced confidence, and explicit limited-evidence warning. The global model threshold remains unchanged.

`ML_MARGINAL_ALERT_BAND` defaults to 0.08 above the saved threshold. The exception is evidence-based, not brand-based: it requires only a missing-authentication finding, a rule score no higher than 8, no medium/high or sensitive-action evidence, no explicit authentication failure, no hidden destination, and organizational alignment for every actionable URL. Capitalization now uses decoded visible prose after removing URLs, domains, encoded fragments, long tracking-like tokens, and short acronyms; at least 40 alphabetic characters and three meaningful uppercase words are required.

The existing 15 phishing fixtures remain non-Safe after fusion (15 Suspicious / 0 Safe), while the model-only fixture confusion matrix remains `[[24,1],[3,12]]` with FPR 0.04 and FNR 0.20. This targeted repair does not establish general inbox accuracy.

Run from the repository root:

```powershell
python services/ml/scripts/verify_legitimate_regressions.py
python services/ml/scripts/evaluate_safe_fixtures.py
```

The first command requires the real model and exact current engine versions; it fails on ML-unavailable or stale results. Its report contains scores, probabilities, URL source types, authentication evidence, and fusion reasons, but no raw email bodies.

## Step 2 historical dataset strategy and language gate

The full corpora, generated CSVs, reports, and model are Git-ignored.

| Corpus | Role | License | Rows used | Limitations |
| --- | --- | --- | ---: | --- |
| [Multiclass NLP Dataset for Phishing and Social Engineering](https://doi.org/10.5281/zenodo.15235123) | Core English, only explicit `Phishing` and `NOT-Malicious General Class` labels | CC BY 4.0 | 287 before cleaning | Email/SMS-like mixture; small; malformed spreadsheet rows require documented repair |
| PhishPhage safe synthetic v2 | Core scenario coverage and 24 targeted training-only anchors | Project-authored, no external data license | 624 | Synthetic wording can create unrealistic shortcuts |
| [Phishing validation emails](https://doi.org/10.5281/zenodo.13474746) | Development benchmark only | CC BY 4.0 | 100 unique of 2,000 | Extreme exact duplication; previously inspected, so not claimed as final untouched evidence |
| [Contextual Email Deception Detection](https://www.kaggle.com/datasets/freshersstaff/contextual-email-deception-detection-dataset) | Final external benchmark | CC0 1.0 | 80 unique of 2,000 | Synthetic and highly templated; balanced classes are unlike an inbox |

`Malware`, `Scareware`, `Baiting`, and `Pretexting` remain separately counted and are excluded from binary training. The Kaggle `spam_indicator` is ignored; spam is never silently mapped to phishing.

Every sample receives a deterministic `langdetect` estimate. The hard gate requires at least 80% English. The current core passes at 99.67% (908/911): 480 English legitimate, 428 English phishing, 0 Spanish legitimate, 0 Spanish phishing, and 3 other/uncertain legitimate estimates. Provenance is 287 real/curated rows (168 English legitimate, 116 English phishing, 3 other/uncertain legitimate), 600 general synthetic rows (300/300), and 24 targeted synthetic training anchors (12/12). Full source/label/language counts are saved in `reports/corpus_audit.json`.

## Cleaning and split policy

- Normalize Unicode and whitespace; remove empty and exact-duplicate text.
- Canonicalize URLs, addresses, domains, numbers, and tokens to form near-template groups.
- Use deterministic `StratifiedGroupKFold` with seed 42. Template groups never cross train, validation, or the internal grouped diagnostic.
- Keep targeted regression anchors explicitly training-only and disclose them.
- Current split: 556 train, 177 validation, 178 internal grouped diagnostic.
- Candidate and threshold selection use validation only.
- The internal grouped diagnostic was inspected during development and is not called untouched. The reset CC0 external benchmark was sealed after corpus construction and evaluated once after the model and threshold were locked.
- `reports/split_manifest.json` stores SHA-256 text hashes, never raw bodies.

## Step 2 historical candidates and selected configuration

All candidates use balanced class weights and seed 42:

1. Word TF-IDF (1,2) + Logistic Regression.
2. Word TF-IDF (1,2) + character `char_wb` TF-IDF (3,5) + Logistic Regression.
3. Word TF-IDF (1,2) + character `char_wb` TF-IDF (3,5) + `LinearSVC`, calibrated with five-fold sigmoid calibration inside training data.

Both feature branches use lowercase text, Unicode accent stripping, sublinear TF, and at most 30,000 features per branch. Candidate C was selected. Its validation Brier score improved from 0.1701 for a raw decision-score sigmoid to 0.0571 after calibration. Calibration buckets are in `reports/calibration_analysis.json`.

The selected threshold is 0.500. Thresholds 0.200–0.700 in 0.025 steps were compared on validation only. The policy minimizes false negatives subject to FPR <= 12%, then considers PR-AUC and F1. The retired Step 1 threshold 0.35 was validation-selected, but its Spanish-heavy corpus and repeatedly inspected test output make it unsuitable for Step 2 claims.

## Step 2 historical results

Phishing is the positive class. `[[TN, FP], [FN, TP]]` is used below.

| Evaluation | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR | Brier | Matrix |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Validation (selection) | 0.9944 | 1.0000 | 0.9880 | 0.9939 | 0.9882 | 0.9937 | 0.0000 | 0.0120 | 0.0571 | `[[94,0],[1,82]]` |
| Internal grouped diagnostic | 0.5674 | 0.5283 | 0.6747 | 0.5926 | 0.7973 | 0.8269 | 0.5263 | 0.3253 | 0.2765 | `[[45,50],[27,56]]` |
| Final external benchmark | 0.9125 | 0.8837 | 0.9500 | 0.9157 | 0.9831 | 0.9829 | 0.1250 | 0.0500 | 0.0650 | `[[35,5],[2,38]]` |

The sharp validation/internal gap is important evidence of template/source shift. The external result is encouraging but comes from only 80 unique synthetic templates. None of these numbers establish production accuracy.

The 50 tracked fixtures contain 15 phishing, 15 legitimate, 10 hard negatives, 5 planned disagreement cases, and 5 incomplete inputs. They include fake jobs, banking, government/tax, cryptocurrency, MFA/OTP, QR-lure, and support scenarios even where core-corpus coverage is thin. Current model-only fixture results are `[[24,1],[3,12]]`: 20% FNR and 4% FPR, with 16 rule/ML disagreements after the rules/fusion repair. This deliberately difficult set reinforces both false-negative and distribution-shift limitations.

## Rebuild and provision

Run from the repository root with the ML environment:

```powershell
python services/ml/scripts/build_english_corpus.py `
  --core-source services/ml/data/raw/phishing_nlp_dataset.xlsx `
  --external-source services/ml/data/raw/phishing_validation_emails.csv `
  --final-benchmark-source services/ml/data/external/contextual_email_deception_cc0.csv `
  --output services/ml/data/processed/english_core.csv `
  --external-output services/ml/data/external/development_benchmark.csv `
  --final-benchmark-output services/ml/data/external/final_external_benchmark.csv `
  --audit-output services/ml/reports/corpus_audit.json

python services/ml/scripts/train_model.py `
  --dataset services/ml/data/processed/english_core.csv `
  --model-output services/ml/models/phishshield_model.joblib `
  --metrics-output services/ml/reports/evaluation_metrics.json

python services/ml/scripts/evaluate_model.py `
  --dataset services/ml/data/external/validation.csv `
  --model services/ml/models/phishshield_model.joblib `
  --output services/ml/reports/external_evaluation.json

python services/ml/scripts/verify_api_integration.py
python services/ml/scripts/evaluate_safe_fixtures.py
python services/ml/scripts/verify_legitimate_regressions.py
```

Generated artifacts include the compatible Joblib bundle, `metadata.json`, `evaluation_metrics.json`, `threshold_analysis.json`, `calibration_analysis.json`, `corpus_audit.json`, `split_manifest.json`, `error_analysis.md`, `training_summary.md`, `api_verification.json`, `fixture_evaluation.json`, and `legitimate_regression.json`.

The current Step 3 model is 454,776 bytes at `services/ml/models/phishshield_model.joblib`. Do not commit it automatically. Deployment artifact/object storage with checksums and version promotion is preferred; Git LFS is acceptable only if the team intentionally versions model binaries with source.

## Analysis completeness and limitations

The API now reports `body_text_only`, `structured_fields`, `html_content`, or `complete_raw_email`, plus evidence-availability booleans. A Safe decision based on incomplete evidence is explicitly qualified and capped at 0.65 confidence. HTML anchors are parsed locally; visible-domain versus real-`href` mismatches and defanged indicators are analyzed without fetching, resolving, or executing any destination.

The selected model remains text-only because feature set A won. Candidate C can derive structured indicators from supplied raw text/headers, but it does not establish sender reputation, validate SPF/DKIM/DMARC, inspect attachment content, render HTML, follow redirects, or use external threat intelligence. Real inbox prevalence, multilingual mail, thread history, image-only lures, compromised legitimate accounts, and novel campaigns can behave very differently.

See `REGRESSION_REPORT.md` for the Facebook impersonation before/after record.
