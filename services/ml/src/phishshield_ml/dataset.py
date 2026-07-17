"""Dataset loading, validation, duplicate removal, and splitting."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from .preprocessing import normalize_email_text, validate_training_text
from .schemas import DatasetSummary, SplitSummary


LABEL_MAPPING = {"legitimate": 0, "phishing": 1, "0": 0, "1": 1, 0: 0, 1: 1}

REQUIRED_COLUMNS = {"text", "label"}


@dataclass(frozen=True)
class PreparedDataset:
    dataframe: pd.DataFrame
    summary: DatasetSummary


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

    labels = []
    for label in frame["label"]:
        if label in LABEL_MAPPING:
            labels.append(LABEL_MAPPING[label])
        elif isinstance(label, str) and label.strip().lower() in LABEL_MAPPING:
            labels.append(LABEL_MAPPING[label.strip().lower()])
        else:
            raise ValueError(f"Unsupported label value: {label!r}")
    frame["label"] = labels

    before = len(frame)
    frame = frame.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    removed = before - len(frame)

    counts = Counter(frame["label"].tolist())
    if 0 not in counts or 1 not in counts:
        raise ValueError("Dataset must contain both legitimate and phishing classes")

    summary = DatasetSummary(
        input_rows=input_rows,
        total_rows=len(frame),
        legitimate_count=counts[0],
        phishing_count=counts[1],
        empty_rows_removed=empty_rows_removed,
        duplicate_rows_removed=removed,
    )
    frame.attrs["dataset_summary"] = summary
    return frame


def prepare_dataset(dataset_path: str | Path) -> PreparedDataset:
    frame = load_and_validate_dataset(dataset_path)
    summary = frame.attrs["dataset_summary"]
    return PreparedDataset(dataframe=frame, summary=summary)


def split_dataset(frame: pd.DataFrame, random_state: int = 42) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, SplitSummary]:
    if frame["label"].nunique() < 2:
        raise ValueError("Dataset must contain both classes")

    min_class_count = frame["label"].value_counts().min()
    if min_class_count < 3 or len(frame) < 10:
        raise ValueError("Dataset too small for stratified splitting")

    train_frame, temp_frame = train_test_split(
        frame,
        test_size=0.30,
        random_state=random_state,
        stratify=frame["label"],
    )
    valid_frame, test_frame = train_test_split(
        temp_frame,
        test_size=0.50,
        random_state=random_state,
        stratify=temp_frame["label"],
    )

    train_texts = set(train_frame["text"])
    valid_frame = valid_frame[~valid_frame["text"].isin(train_texts)].copy()
    test_frame = test_frame[~test_frame["text"].isin(train_texts)].copy()
    valid_frame = valid_frame[~valid_frame["text"].isin(set(test_frame["text"]))].copy()

    summary = SplitSummary(train_rows=len(train_frame), validation_rows=len(valid_frame), test_rows=len(test_frame))
    return train_frame.reset_index(drop=True), valid_frame.reset_index(drop=True), test_frame.reset_index(drop=True), summary
