# Dataset Acquisition and Corpus Audit

This is the reproducible, review-gated input pipeline for the English-first academic baseline. It does not train or provision a model. Raw messages and all generated corpora remain Git-ignored.

## Source audit

The machine-readable source of truth is `dataset_sources.json`, audited 2026-07-17.

| Source | Intended role | Official rights/download result | Pipeline status |
| --- | --- | --- | --- |
| [CMU Enron Email Dataset](https://www.cs.cmu.edu/~enron/) | Legitimate English workplace email | CMU provides a current archive for research and warns about privacy, but states no explicit reusable content license or official checksum | Blocked: unclear license/privacy-sensitive content |
| [Apache SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html) `easy_ham` | Legitimate email | Official direct archive exists; the README says message copyright remains with original senders | Blocked: no dataset-wide reuse license |
| SpamAssassin `hard_ham` | Legitimate hard negatives | Same rights condition as `easy_ham` | Blocked: no dataset-wide reuse license |
| SpamAssassin `spam` | Generic spam hard negatives | Same rights condition; source label means spam, not phishing | Blocked and never mapped to phishing |
| [Zenodo 15235123](https://zenodo.org/records/15235123) | English phishing positives | CC BY 4.0; direct XLSX; official MD5 `7213a3ee515a713f4eee2a6948f1756e` | Approved; only explicit `Phishing` rows become label `1` |
| [Zenodo 13474746](https://zenodo.org/records/13474746) | External validation only | CC BY 4.0; direct CSV; official MD5 `1bf8ec0fe3f67e12dd275ce5b2b91b69` | Approved; physically isolated under `data/external/` |
| [SpaPhish](https://data.mendeley.com/datasets/hz2d6gz7pc/5) | Optional Spanish supplement | Version 5 indicates CC BY 4.0, but a stable unauthenticated official direct file URL was not verified | Blocked; excluded from the core English model |
| PhishTank/OpenPhish | URL reputation only | Not audited as email corpora | Excluded; never converted to email-body labels |

This conservative gate means the currently approved core acquisition has phishing positives but no approved legitimate class. Corpus preparation therefore cannot produce a trainable binary dataset. Do not substitute generic spam for phishing or silently use an unlicensed corpus to fill the missing class.

## Reproduce the audit

Run from the repository root with the ML virtual environment. The dry run performs no network request:

```powershell
services/ml/.venv/Scripts/python.exe services/ml/scripts/download_datasets.py --dry-run
```

Download the approved core and physically isolated external files:

```powershell
services/ml/.venv/Scripts/python.exe services/ml/scripts/download_datasets.py
services/ml/.venv/Scripts/python.exe services/ml/scripts/verify_downloads.py --strict
```

Prepare, audit languages, remove duplicates/templates, and stage grouped splits only if both approved classes exist:

```powershell
services/ml/.venv/Scripts/python.exe services/ml/scripts/prepare_english_corpus.py
services/ml/.venv/Scripts/python.exe services/ml/scripts/audit_languages.py
services/ml/.venv/Scripts/python.exe services/ml/scripts/deduplicate_and_group.py
```

Review these generated, Git-ignored files before any training decision:

- `data/interim/download_manifest.json`
- `data/interim/verification_report.json`
- `data/interim/preparation_audit.json`
- `data/interim/language_audit.json`
- `data/interim/deduplication_and_split_audit.json`
- `data/processed/english_core/review_corpus.csv`
- `data/external/processed/validation.csv` (full derived external set; never a training input)

Every source audit records its official page, exact download URL, license, expected and computed checksums, download date, archive filename, source-label meaning, assigned project label, role, language distribution, and accepted/rejected counts. Missing, changed, authentication-gated, unavailable, or license-unclear sources are reported and not bypassed.

## Parsing and safety contract

RFC822/MIME archives are parsed locally. The parser extracts subject, plain body, sanitized HTML text, sender domain, Reply-To domain, URLs as inert strings, available authentication headers, and attachment filename/content-type/byte-count metadata. It does not:

- execute or inspect attachment content;
- render HTML, JavaScript, SVG, styles, or templates;
- request URLs, images, forms, redirects, or domains found inside messages;
- send messages through a live mail system;
- query DNS, reputation feeds, or external threat intelligence.

Archive members with absolute paths, traversal segments, symbolic links, or hard links are rejected. A verified source checksum is required when the official repository publishes one.

## Cleaning, language, and leakage controls

Core records with empty text, malformed labels, or non-English language estimates are rejected. Exact SHA-256 duplicates, canonical template duplicates, and close 64-bit SimHash template matches are removed. Volatile URLs, domains, addresses, numbers, and long tokens are normalized for template comparison.

Remaining messages receive deterministic source/campaign group IDs while retaining separate template hashes. If a viable two-class corpus is eventually approved, `StratifiedGroupKFold` with seed 42 keeps each source campaign in one split; global template removal prevents near-identical templates from crossing splits. The external validation directory is rejected as a core input path and is never read by the deduplication/splitting script.

## Limitations

Language detection is statistical and can misclassify short messages. Campaign identities are inferred from archive layout or normalized templates when publishers do not supply them. Near-duplicate thresholds trade false merges against leakage. Enron and SpamAssassin are old corpora and may not represent modern inboxes even if their rights are later cleared. The approved Zenodo phishing corpus is small and mixes email with SMS-like text; the validation corpus is highly repetitive and partly artificial. These data and the downstream TF-IDF baseline do not establish production-grade accuracy.
