# PhishPhage ML Academic Baseline

This package trains and provisions the local text classifier used by the existing API pipeline. It is an explainable academic baseline, not production-grade phishing protection.

## Dataset sources

The provisioned model uses two public, license-clear datasets:

1. [SpaPhish v5](https://doi.org/10.17632/hz2d6gz7pc.5), CC BY 4.0: 1,395 anonymized real-world Spanish emails collected from 2014–2025, with 664 legitimate and 731 phishing messages. Subject and body are combined; derived technical and persuasion fields are not model features.
2. [Phishing validation emails](https://doi.org/10.5281/zenodo.13474746), CC BY 4.0: 2,000 English messages advertised as an even safe/phishing mix. It combines real-world and artificial examples and was published for validation. Exact-text cleaning leaves only 100 unique messages (77 legitimate and 23 phishing), so it is used only as a small English supplement.

The Mendeley “Spam E-mail and Phishing Detection” dataset (DOI `10.17632/shj94nrczy.1`) was inspected but rejected: its email file is the 5,572-message ham/spam SMS-style corpus, not a phishing-email corpus. URL-only and license-unclear aggregations are also excluded.

Raw and processed datasets are Git-ignored. Do not commit email corpora.

## Preparation and split

The preparation command maps both sources to:

- `text`
- `label`, where `0 = legitimate` and `1 = phishing`

It combines SpaPhish subject/body, applies Unicode and whitespace normalization, removes empty text, and removes exact duplicate normalized text before any split. The current preparation result is:

- source rows: 3,395 (1,664 legitimate, 1,731 phishing)
- empty rows removed: 0
- exact duplicate texts removed: 1,900
- clean rows: 1,495 (741 legitimate, 754 phishing)

Training uses a deterministic, label-stratified 70/15/15 split with random seed `42`: 1,046 train, 224 validation, and 225 test rows. Deduplication precedes splitting, and the split helper also checks for text overlap.

## Exact model configuration

- `TfidfVectorizer`
  - lowercase: `True`
  - n-grams: unigrams and bigrams `(1, 2)`
  - `min_df=1`
  - `max_df=0.95`
  - `max_features=20000`
  - `sublinear_tf=True`
  - `strip_accents="unicode"`
- `LogisticRegression`
  - `class_weight="balanced"`
  - `random_state=42`
  - `solver="liblinear"`
  - `max_iter=1000`

Phishing is always the positive class.

## Evaluation and selected threshold

Threshold selection is performed on validation data only. Thresholds from `0.10` through `0.90` are evaluated in `0.05` increments. The policy first limits validation false-positive rate to at most 10%, then minimizes false-negative rate, then maximizes F1.

The selected threshold is `0.35`:

| Split | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Confusion matrix `[[TN,FP],[FN,TP]]` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Train | 0.9723 | 0.9479 | 1.0000 | 0.9733 | 0.9996 | 0.0560 | 0.0000 | `[[489,29],[0,528]]` |
| Validation | 0.9375 | 0.9091 | 0.9735 | 0.9402 | 0.9908 | 0.0991 | 0.0265 | `[[100,11],[3,110]]` |
| Test | 0.9289 | 0.8943 | 0.9735 | 0.9322 | 0.9905 | 0.1161 | 0.0265 | `[[99,13],[3,110]]` |

At the default `0.50` test threshold, recall falls to `0.8319` and FNR rises to `0.1681`, although FPR falls to `0.0089`. The `0.35` choice intentionally trades more false positives for substantially fewer dangerous false negatives.

These scores are strongly affected by source/language artifacts and the highly duplicated English source. They must not be presented as production accuracy.

## Commands

Run from `services/ml` using the ML environment (the current checkout can also use `apps/api/.venv`):

```powershell
python scripts/prepare_dataset.py `
  --source data/raw/phishing_validation_emails.csv `
  --spaphish-source data/raw/spaphish_v5.csv `
  --output data/processed/phishing_email_dataset.csv `
  --summary-output reports/dataset_summary.json

python scripts/train_model.py `
  --dataset data/processed/phishing_email_dataset.csv `
  --model-output models/phishshield_model.joblib `
  --metrics-output reports/evaluation_metrics.json

python scripts/verify_api_integration.py
```

Validation:

```powershell
pytest tests/ -v
python -m compileall src scripts
```

## Generated local artifacts

- `models/phishshield_model.joblib` — compatible pipeline bundle, selected threshold included
- `reports/metadata.json`
- `reports/evaluation_metrics.json`
- `reports/threshold_analysis.json`
- `reports/dataset_summary.json`
- `reports/error_analysis.md` — safe summaries only; no raw bodies, addresses, or URLs
- `reports/training_summary.md`
- `reports/api_verification.json`

All paths are Git-ignored. The default compatibility filename remains `phishshield_model.joblib`.

## Limitations

- The training mix is mostly Spanish real-world email plus a very small set of unique English messages.
- The English source mixes synthetic and real examples and has extreme duplication.
- Random row splits can overestimate generalization when messages share campaign/source style; future work should use source-, time-, and campaign-separated external evaluation.
- The model sees text only. It does not inspect email authentication, sender reputation, rendered HTML, attachment content, or URL destinations.
- Balanced evaluation does not represent a production inbox's class prevalence.
- Legitimate support/security vocabulary can produce false positives, and short delivery/invoice scams can be missed.
- No external threat intelligence, deep learning, or additional model family is used in this phase.

## API integration

The API resolves `ML_MODEL_PATH` from the repository root; its default is `services/ml/models/phishshield_model.joblib`. Older compatible bundles without a saved threshold use `0.50`; this bundle uses its validated `0.35` threshold. For deployments that require ML, set `ML_REQUIRED=true` so missing or invalid artifacts return HTTP 503 instead of rule-only fallback.
