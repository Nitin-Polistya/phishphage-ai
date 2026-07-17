# Local ML Data

All downloaded and generated corpora are local, Git-ignored inputs. Do not commit complete email datasets.

- `raw/phishing_nlp_dataset.xlsx`: Zenodo 10.5281/zenodo.15235123, CC BY 4.0.
- `raw/phishing_validation_emails.csv`: Zenodo 10.5281/zenodo.13474746, CC BY 4.0; development-only after exact deduplication.
- `raw/contextual_email_deception_cc0/`: Kaggle Contextual Email Deception Detection, CC0 1.0; reset final benchmark.
- `processed/english_core.csv`: `text,label` plus provenance, scenario, language, and template-group audit fields.
- `processed/development_benchmark.csv`: previously inspected 100-row Zenodo benchmark.
- `processed/final_external_benchmark.csv`: sealed 80-unique-row CC0 benchmark.

Labels are always `0 = legitimate`, `1 = phishing`. Malware, scareware, baiting, pretexting, and spam metadata are not silently converted to phishing. Preparation removes empty/exact duplicates, estimates every sample's language, enforces the 80% English gate, and assigns near-template groups before splitting.
