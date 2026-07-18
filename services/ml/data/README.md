# Local ML Data

All downloaded and generated corpora are local, Git-ignored inputs. Do not commit complete email datasets or generated private message content.

- `raw/`: approved training-corpus downloads only.
- `interim/`: download manifests, source audits, parsed training candidates, language rejections, and deduplication statistics.
- `processed/`: review corpora, grouped diagnostics, and model-ready training CSVs.
- `external/`: flat, physically isolated external-validation downloads and derived evaluation files; never training input.
- `staging/`: controlled future acquisition batches; each batch contains a manifest plus `raw/`, `normalized/`, `validation/`, and `reports/`. Nothing here is a development input.

The directory layout contains the lifecycle siblings `raw/`, `interim/`, `processed/`, `external/`, and `staging/`. Do not create lifecycle subdirectories inside `external/`; batch subdirectories are allowed only inside `staging/`.

External benchmark archives, publisher downloads, parsed derivatives, development benchmarks, and final evaluation CSVs all remain flat inside `external/`. Training and corpus-selection scripts must not read that directory; standalone post-lock evaluation may read it explicitly.

The reviewed registry is `../dataset_sources.json`; process and source decisions are in `../DATASET_ACQUISITION.md`. Labels are always `0 = legitimate`, `1 = phishing`. Generic spam remains an unlabeled hard-negative pool and is never automatically treated as phishing. External validation is never used for training, candidate selection, or threshold selection.
