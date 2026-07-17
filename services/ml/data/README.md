# Local ML Data

All downloaded and generated corpora are local, Git-ignored inputs. Do not commit complete email datasets or generated private message content.

- `raw/`: approved training-corpus downloads only.
- `interim/`: download manifests, source audits, parsed candidates, language rejections, and deduplication statistics.
- `processed/english_core/`: review corpus and, only when viable, grouped train/validation/test CSVs.
- `external/raw/`: untouched external-validation download, physically separate from training inputs.
- `external/interim/`: derived external parsing/language audit, never training input.

The reviewed registry is `../dataset_sources.json`; process and source decisions are in `../DATASET_ACQUISITION.md`. Labels are always `0 = legitimate`, `1 = phishing`. Generic spam remains an unlabeled hard-negative pool and is never automatically treated as phishing. External validation is never used for training, candidate selection, or threshold selection.
