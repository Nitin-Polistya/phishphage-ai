from pathlib import Path

import pandas as pd
import pytest

from phishshield_ml.dataset import load_and_validate_dataset, prepare_dataset, split_dataset


def _write_csv(path: Path, rows: list[dict]) -> Path:
    frame = pd.DataFrame(rows)
    frame.to_csv(path, index=False)
    return path


def test_valid_csv(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [
        {"text": "Hello world", "label": "legitimate"},
        {"text": "Urgent verify password", "label": "phishing"},
        {"text": "Another hello", "label": "0"},
        {"text": "Click login", "label": "1"},
    ])
    frame = load_and_validate_dataset(dataset)
    assert len(frame) == 4


def test_missing_columns(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [{"text": "Hello"}])
    with pytest.raises(ValueError):
        load_and_validate_dataset(dataset)


def test_unsupported_labels(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [{"text": "Hello", "label": "spam"}, {"text": "Bye", "label": "legitimate"}])
    with pytest.raises(ValueError):
        load_and_validate_dataset(dataset)


def test_empty_rows(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [{"text": " ", "label": "legitimate"}, {"text": "Bad", "label": "phishing"}])
    with pytest.raises(ValueError):
        load_and_validate_dataset(dataset)


def test_duplicate_removal(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [
        {"text": "Dup", "label": "legitimate"},
        {"text": "Dup", "label": "phishing"},
        {"text": "Unique legit", "label": "legitimate"},
        {"text": "Unique phish", "label": "phishing"},
    ])
    frame = load_and_validate_dataset(dataset)
    assert len(frame) == 3


def test_class_counts_and_single_class_rejection(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [
        {"text": "A", "label": "legitimate"},
        {"text": "B", "label": "legitimate"},
        {"text": "C", "label": "legitimate"},
        {"text": "D", "label": "legitimate"},
    ])
    with pytest.raises(ValueError):
        load_and_validate_dataset(dataset)


def test_dataset_too_small_for_split(tmp_path):
    dataset = _write_csv(tmp_path / "dataset.csv", [
        {"text": f"L{i}", "label": "legitimate"} for i in range(3)
    ] + [
        {"text": f"P{i}", "label": "phishing"} for i in range(3)
    ])
    frame = load_and_validate_dataset(dataset)
    with pytest.raises(ValueError):
        split_dataset(frame)
