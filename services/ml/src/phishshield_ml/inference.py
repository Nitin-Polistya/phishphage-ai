"""Local inference helper for the saved ML bundle."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Iterable

import joblib

from .preprocessing import normalize_email_text, validate_training_text
from .schemas import ExplainabilityTerm, InferenceResult, LoadedModelBundle


class ModelLoadError(RuntimeError):
    pass


def load_model_bundle(model_path: str | Path) -> LoadedModelBundle:
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(f"Model bundle not found: {path}")
    bundle = joblib.load(path)
    return LoadedModelBundle(
        pipeline=bundle["pipeline"],
        model_version=bundle["model_version"],
        label_mapping=bundle["label_mapping"],
        preprocessing_version=bundle["preprocessing_version"],
        feature_config=bundle["feature_config"],
        training_timestamp=bundle["training_timestamp"],
        dataset_summary=bundle["training_dataset_summary"],
        evaluation_metrics=bundle["evaluation_metrics"],
    )


class LocalInferenceService:
    def __init__(self, model_path: str | Path):
        self._bundle = load_model_bundle(model_path)
        self._pipeline = self._bundle.pipeline
        self._vectorizer = self._pipeline.named_steps["tfidf"]
        self._classifier = self._pipeline.named_steps["clf"]

    @property
    def model_version(self) -> str:
        return self._bundle.model_version

    def predict(self, text: str, top_k: int = 5) -> InferenceResult:
        normalized = validate_training_text(text)
        probabilities = self._pipeline.predict_proba([normalized])[0]
        legitimate_probability = float(probabilities[0])
        phishing_probability = float(probabilities[1])
        predicted_label = "phishing" if phishing_probability >= 0.5 else "legitimate"
        phishing_terms, legitimate_terms = self._explain(normalized, top_k=top_k)
        return InferenceResult(
            predicted_label=predicted_label,
            phishing_probability=phishing_probability,
            legitimate_probability=legitimate_probability,
            model_version=self.model_version,
            top_phishing_terms=phishing_terms,
            top_legitimate_terms=legitimate_terms,
        )

    def _explain(self, text: str, top_k: int = 5) -> tuple[list[ExplainabilityTerm], list[ExplainabilityTerm]]:
        vector = self._vectorizer.transform([text])
        feature_names = self._vectorizer.get_feature_names_out()
        coefs = self._classifier.coef_[0]
        indices = vector.nonzero()[1]
        contributions = []
        for index in indices:
            value = vector[0, index]
            contribution = float(value * coefs[index])
            contributions.append((feature_names[index], contribution))
        phishing = [ExplainabilityTerm(term=term, contribution=contrib) for term, contrib in sorted(contributions, key=lambda item: item[1], reverse=True) if contrib > 0][:top_k]
        legitimate = [ExplainabilityTerm(term=term, contribution=contrib) for term, contrib in sorted(contributions, key=lambda item: item[1]) if contrib < 0][:top_k]
        return phishing, legitimate
