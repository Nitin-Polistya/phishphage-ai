from pathlib import Path

import joblib
import pandas as pd

from phishshield_ml.training import train_model


def _balanced_dataset(path: Path) -> Path:
    rows = []
    for i in range(10):
        rows.append({"text": f"Legitimate message {i}", "label": "legitimate"})
        rows.append({"text": f"Urgent verify password {i}", "label": "phishing"})
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_model_trains_and_saves_bundle(tmp_path):
    dataset = _balanced_dataset(tmp_path / "dataset.csv")
    model_path = tmp_path / "models" / "bundle.joblib"
    metrics_path = tmp_path / "reports" / "metrics.json"
    summary = train_model(dataset, model_path, metrics_path)
    assert model_path.exists()
    assert metrics_path.exists()
    assert summary.model_version.startswith("ml-baseline")


def test_metadata_excludes_raw_text(tmp_path):
    dataset = _balanced_dataset(tmp_path / "dataset.csv")
    model_path = tmp_path / "bundle.joblib"
    metrics_path = tmp_path / "metrics.json"
    train_model(dataset, model_path, metrics_path)
    bundle = joblib.load(model_path)
    assert "Legitimate message" not in str(bundle)
    assert "Urgent verify password" not in str(bundle)


def test_metrics_within_ranges(tmp_path):
    dataset = _balanced_dataset(tmp_path / "dataset.csv")
    model_path = tmp_path / "bundle.joblib"
    metrics_path = tmp_path / "metrics.json"
    summary = train_model(dataset, model_path, metrics_path)
    for metric in (summary.validation_metrics, summary.test_metrics):
        assert 0.0 <= metric.accuracy <= 1.0
        assert 0.0 <= metric.precision <= 1.0
        assert 0.0 <= metric.recall <= 1.0
        assert 0.0 <= metric.f1 <= 1.0


def test_fixed_random_seed_stable_split_sizes(tmp_path):
    dataset = _balanced_dataset(tmp_path / "dataset.csv")
    model_path1 = tmp_path / "bundle1.joblib"
    metrics_path1 = tmp_path / "metrics1.json"
    model_path2 = tmp_path / "bundle2.joblib"
    metrics_path2 = tmp_path / "metrics2.json"
    s1 = train_model(dataset, model_path1, metrics_path1)
    s2 = train_model(dataset, model_path2, metrics_path2)
    assert s1.split_summary == s2.split_summary
