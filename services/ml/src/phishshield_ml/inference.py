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


class ModelAdapterError(ModelLoadError):
    """The approved artifact does not expose a supported prediction contract."""


class ModelAdapter:
    """Small, explicit adapter for approved direct and calibrated estimators.

    Prediction always goes through the object's public ``predict_proba``.  A
    wrapped pipeline is exposed only for explainability and diagnostics.
    """

    def __init__(self, predictor: object, label_mapping: dict[str, int]):
        predict_proba = getattr(predictor, "predict_proba", None)
        if not callable(predict_proba):
            raise ModelAdapterError("Approved model does not support calibrated probability inference")
        self.predictor = predictor
        self.label_mapping = self._validate_label_mapping(label_mapping)
        self.pipeline = getattr(predictor, "pipeline", None)

    @staticmethod
    def _validate_label_mapping(mapping: dict[str, int]) -> dict[str, int]:
        if set(mapping) != {"legitimate", "phishing"}:
            raise ModelAdapterError("Approved model label mapping is unsupported")
        indices = list(mapping.values())
        if mapping != {"legitimate": 0, "phishing": 1} or sorted(indices) != [0, 1]:
            raise ModelAdapterError("Approved model class ordering is unsupported")
        return dict(mapping)

    def predict_proba(self, text: str) -> tuple[float, float]:
        try:
            values = np.asarray(self.predictor.predict_proba([text]), dtype=float)
        except Exception as error:
            raise ModelAdapterError("Approved model probability inference failed") from error
        if values.shape != (1, 2) or not np.isfinite(values).all():
            raise ModelAdapterError("Approved model returned an invalid probability shape")
        if np.any(values < 0) or np.any(values > 1):
            raise ModelAdapterError("Approved model returned an invalid probability")
        # The serialized CalibratedModel returns [legitimate, phishing].  For
        # estimators exposing classes_, validate that their columns agree with
        # the registry-backed mapping before selecting the phishing class.
        classes = getattr(self.predictor, "classes_", None)
        if classes is not None and list(classes) != [self.label_mapping["legitimate"], self.label_mapping["phishing"]]:
            raise ModelAdapterError("Approved model class ordering does not match label mapping")
        return float(values[0, self.label_mapping["legitimate"]]), float(values[0, self.label_mapping["phishing"]])


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
        self._adapter = ModelAdapter(self._bundle.pipeline, self._bundle.label_mapping)
        self._pipeline = self._adapter.pipeline
        self._vectorizer, self._classifier = self._diagnostic_components()

    @classmethod
    def from_verified_model(cls, loaded_model) -> "LocalInferenceService":
        """Create an inference service from a registry/hash-verified model."""
        instance = cls.__new__(cls)
        instance._bundle = cls._bundle_from_verified_model(loaded_model)
        instance._adapter = ModelAdapter(instance._bundle.pipeline, instance._bundle.label_mapping)
        instance._pipeline = instance._adapter.pipeline
        instance._vectorizer, instance._classifier = instance._diagnostic_components()
        return instance

    def _diagnostic_components(self):
        steps = getattr(self._pipeline, "named_steps", {})
        if not isinstance(steps, dict):
            return None, None
        return steps.get("features") or steps.get("tfidf"), steps.get("clf")

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
        legitimate_probability, phishing_probability = self._adapter.predict_proba(normalized)
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
        if self._vectorizer is None or self._classifier is None:
            return [], []
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
        if len(coefs) != len(feature_names):
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
