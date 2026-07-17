"""Dataset validation, language auditing, deduplication, and grouped splitting."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from langdetect import DetectorFactory, LangDetectException, detect_langs
from sklearn.model_selection import StratifiedGroupKFold

from .preprocessing import normalize_email_text
from .schemas import DatasetSummary, SplitSummary


LABEL_MAPPING = {"legitimate": 0, "phishing": 1, "0": 0, "1": 1, 0: 0, 1: 1}
REQUIRED_COLUMNS = {"text", "label"}
MIN_ENGLISH_PERCENTAGE = 80.0
DetectorFactory.seed = 42


@dataclass(frozen=True)
class PreparedDataset:
    dataframe: pd.DataFrame
    summary: DatasetSummary


def estimate_language(text: str) -> tuple[str, float]:
    """Return a deterministic ISO language estimate and confidence."""
    try:
        estimates = detect_langs(text[:10000])
    except LangDetectException:
        return "unknown", 0.0
    if not estimates:
        return "unknown", 0.0
    best = estimates[0]
    return best.lang, float(best.prob)


def canonicalize_template(text: str) -> str:
    """Remove volatile tokens so near-identical templates share a split group."""
    value = text.lower()
    value = re.sub(r"h(?:tt|xx)ps?://\S+|www\.\S+", " <url> ", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " <email> ", value)
    value = re.sub(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " <domain> ", value)
    value = re.sub(r"\b\d+(?:[.,:/-]\d+)*\b", " <number> ", value)
    value = re.sub(r"\b[a-f0-9]{8,}\b", " <token> ", value)
    return re.sub(r"\s+", " ", value).strip()


def _template_hash(text: str) -> str:
    return hashlib.sha256(canonicalize_template(text).encode("utf-8")).hexdigest()[:20]


def load_and_validate_dataset(dataset_path: str | Path) -> pd.DataFrame:
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    frame = frame.copy()
    input_rows = len(frame)
    frame["text"] = frame["text"].map(normalize_email_text)
    empty_mask = frame["text"].eq("")
    empty_rows_removed = int(empty_mask.sum())
    frame = frame.loc[~empty_mask].copy()
    labels: list[int] = []
    for label in frame["label"]:
        key = label.strip().lower() if isinstance(label, str) else label
        if key not in LABEL_MAPPING:
            raise ValueError(f"Unsupported label value: {label!r}")
        labels.append(LABEL_MAPPING[key])
    frame["label"] = labels

    before = len(frame)
    frame = frame.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    removed = before - len(frame)
    counts = Counter(frame["label"].tolist())
    if 0 not in counts or 1 not in counts:
        raise ValueError("Dataset must contain both legitimate and phishing classes")

    if "language" not in frame:
        language_rows = [estimate_language(text) for text in frame["text"]]
        frame["language"] = [language for language, _ in language_rows]
        frame["language_confidence"] = [confidence for _, confidence in language_rows]
    english_count = int(frame["language"].astype(str).str.lower().eq("en").sum())
    english_percentage = 100.0 * english_count / len(frame)
    if english_percentage < MIN_ENGLISH_PERCENTAGE:
        raise ValueError(
            f"English-language gate failed: {english_percentage:.2f}% is below "
            f"the required {MIN_ENGLISH_PERCENTAGE:.0f}%"
        )

    computed_groups = frame["text"].map(_template_hash)
    if "template_group" not in frame:
        frame["template_group"] = computed_groups
    else:
        frame["template_group"] = frame["template_group"].fillna(computed_groups).astype(str)
    if "source" not in frame:
        frame["source"] = "unspecified"
    if "provenance_type" not in frame:
        frame["provenance_type"] = "unspecified"

    summary = DatasetSummary(
        input_rows=input_rows,
        total_rows=len(frame),
        legitimate_count=counts[0],
        phishing_count=counts[1],
        empty_rows_removed=empty_rows_removed,
        duplicate_rows_removed=removed,
        near_duplicate_groups=int(frame["template_group"].nunique()),
        english_count=english_count,
        english_percentage=english_percentage,
    )
    frame.attrs["dataset_summary"] = summary
    return frame


def prepare_dataset(dataset_path: str | Path) -> PreparedDataset:
    frame = load_and_validate_dataset(dataset_path)
    return PreparedDataset(dataframe=frame, summary=frame.attrs["dataset_summary"])


def split_dataset(frame: pd.DataFrame, random_state: int = 42) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, SplitSummary]:
    """Create source/template-group-aware 60/20/20 folds without text leakage."""
    if frame["label"].nunique() < 2 or len(frame) < 20:
        raise ValueError("Dataset too small for grouped stratified splitting")
    roles = frame.get("split_role", pd.Series("development_pool", index=frame.index)).fillna("development_pool")
    fixed_train = frame.loc[roles.eq("train_only")].copy()
    pool = frame.loc[~roles.eq("train_only")].reset_index(drop=True)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    folds = list(splitter.split(pool, pool["label"], groups=pool["template_group"]))
    test_indices = set(folds[0][1].tolist())
    validation_indices = set(folds[1][1].tolist())
    train_indices = set(pool.index) - test_indices - validation_indices
    train_frame = pd.concat([pool.loc[sorted(train_indices)].copy(), fixed_train], ignore_index=True)
    valid_frame = pool.loc[sorted(validation_indices)].copy()
    test_frame = pool.loc[sorted(test_indices)].copy()

    group_sets = [set(part["template_group"]) for part in (train_frame, valid_frame, test_frame)]
    if group_sets[0] & group_sets[1] or group_sets[0] & group_sets[2] or group_sets[1] & group_sets[2]:
        raise RuntimeError("Template-group leakage detected across splits")
    text_sets = [set(part["text"]) for part in (train_frame, valid_frame, test_frame)]
    if text_sets[0] & text_sets[1] or text_sets[0] & text_sets[2] or text_sets[1] & text_sets[2]:
        raise RuntimeError("Exact text leakage detected across splits")
    for name, part in (("train", train_frame), ("validation", valid_frame), ("test", test_frame)):
        if part["label"].nunique() != 2:
            raise ValueError(f"{name} split does not contain both classes")

    summary = SplitSummary(
        train_rows=len(train_frame), validation_rows=len(valid_frame), test_rows=len(test_frame)
    )
    return (
        train_frame.reset_index(drop=True),
        valid_frame.reset_index(drop=True),
        test_frame.reset_index(drop=True),
        summary,
    )
