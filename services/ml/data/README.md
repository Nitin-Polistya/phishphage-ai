# Local ML Data

All downloaded and generated corpora are local, Git-ignored inputs. Do not commit complete email datasets or generated private message content.

- `raw/`: approved training-corpus downloads only.
- `interim/`: download manifests, source audits, parsed training candidates, language rejections, and deduplication statistics.
- `processed/`: review corpora, grouped diagnostics, and model-ready training CSVs.
- `external/`: physically isolated external evaluation files plus explicitly authorized, source-specific ignored acquisition quarantine; never training input.
- `staging/`: controlled future acquisition batches; each batch contains a manifest plus `raw/`, `normalized/`, `validation/`, and `reports/`. Nothing here is a development input.

The directory layout contains the lifecycle siblings `raw/`, `interim/`, `processed/`, `external/`, and `staging/`. Do not create lifecycle subdirectories such as `external/raw`, `external/interim`, or `external/processed`. A source-specific external quarantine such as `external/phishing_pot/` is allowed only when an acquisition task explicitly authorizes it and the entire tree remains ignored.

External benchmarks remain isolated evaluation-only boundaries. Training scripts must not read `external/`; a dedicated controlled-acquisition pilot may read only its explicitly configured quarantine and must pass overlap checks against every configured development and external boundary before staging.

The reviewed registry is `../dataset_sources.json`; process and source decisions are in `../DATASET_ACQUISITION.md`. Labels are always `0 = legitimate`, `1 = phishing`. Generic spam remains an unlabeled hard-negative pool and is never automatically treated as phishing. External validation is never used for training, candidate selection, or threshold selection.
