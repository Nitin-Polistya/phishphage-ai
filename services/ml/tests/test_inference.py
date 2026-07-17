from pathlib import Path

import pandas as pd
import pytest

from phishshield_ml.inference import LocalInferenceService
from phishshield_ml.training import train_model


def _trained_bundle(tmp_path: Path) -> Path:
    rows = []
    for i in range(10):
        rows.append({"text": f"Legitimate message {i}", "label": "legitimate"})
        rows.append({"text": f"Urgent verify password {i}", "label": "phishing"})
    dataset = tmp_path / "dataset.csv"
    pd.DataFrame(rows).to_csv(dataset, index=False)
    model_path = tmp_path / "bundle.joblib"
    metrics_path = tmp_path / "metrics.json"
    train_model(dataset, model_path, metrics_path)
    return model_path


def test_bundle_loads_successfully(tmp_path):
    service = LocalInferenceService(_trained_bundle(tmp_path))
    assert service.model_version.startswith("ml-baseline")


def test_legitimate_and_phishing_predictions(tmp_path):
    service = LocalInferenceService(_trained_bundle(tmp_path))
    legit = service.predict("Hello team, please review the agenda.")
    phish = service.predict("Urgent verify your password now")
    assert 0.0 <= legit.phishing_probability <= 1.0
    assert 0.0 <= phish.phishing_probability <= 1.0
    assert legit.predicted_label in {"legitimate", "phishing"}
    assert phish.predicted_label in {"legitimate", "phishing"}


def test_probabilities_sum_to_one(tmp_path):
    service = LocalInferenceService(_trained_bundle(tmp_path))
    result = service.predict("Verify login now")
    assert pytest.approx(result.phishing_probability + result.legitimate_probability, rel=1e-3) == 1.0


def test_bundle_threshold_is_used(tmp_path):
    path = _trained_bundle(tmp_path)
    import joblib
    bundle = joblib.load(path)
    bundle["decision_threshold"] = 0.0
    joblib.dump(bundle, path)
    assert LocalInferenceService(path).predict("Ordinary project update").predicted_label == "phishing"


def test_empty_input_rejected(tmp_path):
    service = LocalInferenceService(_trained_bundle(tmp_path))
    with pytest.raises(ValueError):
        service.predict("   ")


def test_explainability_terms_limited_and_present(tmp_path):
    service = LocalInferenceService(_trained_bundle(tmp_path))
    result = service.predict("Urgent verify password now please", top_k=3)
    assert len(result.top_phishing_terms) <= 3
    assert all(term.term for term in result.top_phishing_terms)
    assert all(term.term in "Urgent verify password now please".lower() for term in [t for t in result.top_phishing_terms])
