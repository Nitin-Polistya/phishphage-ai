# Data Directory

This directory stores local, user-supplied datasets for the offline PhishPhage ML baseline.

Structure:

- `raw/` - original CSV files supplied by the user
- `processed/` - cleaned split artifacts and summaries

Dataset contract:

- Required columns: `text`, `label`
- Supported label values: `legitimate`, `phishing`, `0`, `1`
- Normalized mapping: `0 = legitimate`, `1 = phishing`
- Optional columns: `subject`, `sender`, `source`, `dataset_split`

No datasets are downloaded automatically.
