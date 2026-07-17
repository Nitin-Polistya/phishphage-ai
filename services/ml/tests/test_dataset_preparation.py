from pathlib import Path

import pandas as pd

from phishshield_ml.scripts.prepare_dataset import prepare_source


def test_selected_source_is_converted_and_cleaned(tmp_path: Path):
    source = tmp_path / "source.csv"
    pd.DataFrame([
        {"Email Text": "Project update", "Email Type": "Safe Email"},
        {"Email Text": "Project update", "Email Type": "Safe Email"},
        {"Email Text": " ", "Email Type": "Safe Email"},
        {"Email Text": "Verify credentials", "Email Type": "Phishing Email"},
    ]).to_csv(source, index=False)
    output = tmp_path / "processed.csv"
    summary_path = tmp_path / "summary.json"

    summary = prepare_source(source, output, summary_path)

    frame = pd.read_csv(output)
    assert list(frame.columns) == ["text", "label"]
    assert frame["label"].tolist() == [0, 1]
    assert summary["cleaning"] == {"empty_rows_removed": 1, "exact_duplicate_texts_removed": 1}
    assert summary_path.exists()


def test_spaphish_subject_and_body_are_combined(tmp_path: Path):
    english = tmp_path / "english.csv"
    pd.DataFrame([
        {"Email Text": "Project update", "Email Type": "Safe Email"},
        {"Email Text": "Verify credentials", "Email Type": "Phishing Email"},
    ]).to_csv(english, index=False)
    spaphish = tmp_path / "spaphish.csv"
    pd.DataFrame([
        {"subject": "Aviso", "body": "Revisa tu cuenta", "Label": 0},
        {"subject": "Urgente", "body": "Confirma tus datos", "Label": 1},
    ]).to_csv(spaphish, index=False)
    output = tmp_path / "processed.csv"

    summary = prepare_source(english, output, tmp_path / "summary.json", spaphish)

    frame = pd.read_csv(output)
    assert "Aviso Revisa tu cuenta" in frame["text"].tolist()
    assert summary["output"]["class_counts"] == {"legitimate": 2, "phishing": 2}
