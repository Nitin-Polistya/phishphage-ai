# PhishPhage ML Baseline

Offline internship-ready machine learning baseline for phishing classification.

## Architecture

This package implements a reproducible local workflow:

1. Load a labeled CSV dataset.
2. Validate required columns and label values.
3. Normalize text conservatively.
4. Remove exact duplicate texts before splitting.
5. Split into train, validation, and test sets.
6. Train a `TF-IDF + Logistic Regression` pipeline.
7. Evaluate metrics.
8. Save a model bundle and metadata JSON.
9. Load the bundle locally for inference.

This baseline is intentionally simple, explainable, and not production-grade protection.

## CSV Format

Required columns:

- `text`
- `label`

Accepted label values:

- `legitimate`
- `phishing`
- `0`
- `1`

Normalized mapping:

- `0` = legitimate
- `1` = phishing

Optional columns:

- `subject`
- `sender`
- `source`
- `dataset_split`

## Preprocessing

The baseline uses conservative preprocessing only:

- Unicode normalization
- line-ending normalization
- whitespace collapsing
- safe string conversion

It preserves URLs, domains, email addresses, numbers, punctuation, and currency symbols.

## Model Configuration

- `TfidfVectorizer`
  - lowercase: `True`
  - ngram_range: `(1, 2)`
  - min_df: configurable
  - max_df: configurable
  - max_features: configurable
  - sublinear_tf: `True`
  - strip_accents: `unicode`
- `LogisticRegression`
  - class_weight: `balanced`
  - random_state: `42`
  - solver: `liblinear`
  - max_iter: configurable

## Split Strategy

- train: 70%
- validation: 15%
- test: 15%
- random_state: `42`
- stratified by label

Exact duplicate texts are removed before splitting, and duplicate leakage across splits is prevented.

## Metrics

Implemented metrics:

- accuracy
- precision
- recall
- F1
- ROC-AUC when probabilities and both classes are available
- confusion matrix
- false-positive rate
- false-negative rate

Phishing is the positive class.

## Model Artifacts

Saved bundle contents:

- fitted pipeline
- model version
- label mapping
- preprocessing version
- feature configuration
- training timestamp
- training dataset summary
- evaluation metrics

Artifacts are written locally and should not be committed.

## Commands

Training:

```powershell
python scripts/train_model.py --dataset data/raw/dataset.csv --model-output models/phishshield_model.joblib --metrics-output reports/metrics.json
```

Evaluation:

```powershell
python scripts/evaluate_model.py --dataset data/raw/dataset.csv --model models/phishshield_model.joblib --output reports/evaluation.json
```

Prediction:

```powershell
python scripts/predict_email.py --model models/phishshield_model.joblib --text "Urgent: verify your password"
```

## Privacy and Security Limitations

- No automatic dataset download
- No network calls
- No external reputation checks
- No Firebase writes
- No authentication integration
- No background workers

Performance depends entirely on the supplied dataset quality and coverage.

## FastAPI integration

The API reads the model location from `ML_MODEL_PATH`. No model bundle is committed by default. With the API's default `ML_REQUIRED=false`, a missing or invalid bundle produces a transparent rule-only response. Set `ML_REQUIRED=true` only in environments where a validated bundle is provisioned and ML must be available.
# ML Service

Initial ML scaffold for PhishPhage AI.
