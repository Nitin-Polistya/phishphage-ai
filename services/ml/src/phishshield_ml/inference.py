"""Local inference helper for the saved ML bundle."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np

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
        decision_threshold=float(bundle.get("decision_threshold", 0.5)),
    )


class LocalInferenceService:
    def __init__(self, model_path: str | Path, verified_model=None):
        self._bundle = self._bundle_from_verified_model(verified_model) if verified_model is not None else load_model_bundle(model_path)
        self._pipeline = self._bundle.pipeline
        self._vectorizer = self._pipeline.named_steps.get("features") or self._pipeline.named_steps.get("tfidf")
        self._classifier = self._pipeline.named_steps["clf"]

    @classmethod
    def from_verified_model(cls, loaded_model) -> "LocalInferenceService":
        """Create an inference service from a registry/hash-verified model."""
        instance = cls.__new__(cls)
        instance._bundle = cls._bundle_from_verified_model(loaded_model)
        instance._pipeline = instance._bundle.pipeline
        instance._vectorizer = instance._pipeline.named_steps.get("features") or instance._pipeline.named_steps.get("tfidf")
        instance._classifier = instance._pipeline.named_steps["clf"]
        return instance

    @staticmethod
    def _bundle_from_verified_model(loaded_model) -> LoadedModelBundle:
        bundle = loaded_model.bundle
        return LoadedModelBundle(
            pipeline=loaded_model.predictor,
            model_version=loaded_model.record.version,
            label_mapping=bundle.get("label_mapping", {"legitimate": 0, "phishing": 1}),
            preprocessing_version=bundle.get("preprocessing_version", "registry-approved"),
            feature_config=bundle.get("feature_config", {}),
            training_timestamp=loaded_model.record.training_timestamp,
            dataset_summary=bundle.get("training_dataset_summary", {}),
            evaluation_metrics=bundle.get("evaluation_metrics", {}),
            decision_threshold=loaded_model.record.threshold,
        )

    @property
    def model_version(self) -> str:
        return self._bundle.model_version

    @property
    def decision_threshold(self) -> float:
        return self._bundle.decision_threshold

    def predict(self, text: str, top_k: int = 5) -> InferenceResult:
        normalized = validate_training_text(text)
        probabilities = self._pipeline.predict_proba([normalized])[0]
        legitimate_probability = float(probabilities[0])
        phishing_probability = float(probabilities[1])
        predicted_label = "phishing" if phishing_probability >= self._bundle.decision_threshold else "legitimate"
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
        if hasattr(self._classifier, "coef_"):
            coefs = self._classifier.coef_[0]
        elif hasattr(self._classifier, "calibrated_classifiers_"):
            coefs = np.mean(
                [calibrated.estimator.coef_[0] for calibrated in self._classifier.calibrated_classifiers_],
                axis=0,
            )
        else:
            return [], []
        indices = vector.nonzero()[1]
        contributions = []
        for index in indices:
            value = vector[0, index]
            contribution = float(value * coefs[index])
            term = str(feature_names[index]).split("__", 1)[-1]
            contributions.append((term, contribution))
        phishing = [ExplainabilityTerm(term=term, contribution=contrib) for term, contrib in sorted(contributions, key=lambda item: item[1], reverse=True) if contrib > 0][:top_k]
        legitimate = [ExplainabilityTerm(term=term, contribution=contrib) for term, contrib in sorted(contributions, key=lambda item: item[1]) if contrib < 0][:top_k]
        return phishing, legitimate
