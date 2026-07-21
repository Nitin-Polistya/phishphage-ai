"""Thread-safe, integrity-checked loading for versioned ML candidates."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

PROJECT_ROOT = Path(__file__).resolve().parents[4]
ML_SRC_PATH = PROJECT_ROOT / "services" / "ml" / "src"
if str(ML_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(ML_SRC_PATH))


class ModelManagerError(RuntimeError):
    code = "model_unavailable"


class ModelIntegrityError(ModelManagerError):
    code = "model_integrity_error"


class ModelVersionError(ModelManagerError):
    code = "unsupported_model_version"


class ModelRegistryError(ModelManagerError):
    code = "invalid_model_registry"


@dataclass(frozen=True)
class ModelRecord:
    model_id: str
    version: str
    artifact_path: Path
    vectorizer_path: Path
    feature_manifest_path: Path
    pipeline_hash: str
    vectorizer_hash: str
    feature_manifest_hash: str
    sha256: str
    calibration: str
    threshold: float
    deployment_candidate: bool
    activated: bool
    compatible_api_version: str
    training_timestamp: str


@dataclass
class LoadedModel:
    record: ModelRecord
    bundle: dict[str, Any]
    loaded_at_ns: int

    @property
    def predictor(self):
        return self.bundle["model"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelManager:
    """Discover and lazily load candidates; registry activation is never changed."""

    def __init__(
        self,
        registry_path: str | Path | None = None,
        compatible_api_version: str = "1",
        selected_model_id: str | None = None,
        artifact_override: str | Path | None = None,
    ):
        self.registry_path = Path(registry_path or PROJECT_ROOT / "services/ml/models/registry.json")
        if not self.registry_path.is_absolute():
            self.registry_path = PROJECT_ROOT / self.registry_path
        self.compatible_api_version = compatible_api_version
        self.selected_model_id = selected_model_id
        self.artifact_override = self._resolve_path(artifact_override) if artifact_override else None
        self._lock = threading.RLock()
        self._records: dict[str, ModelRecord] = {}
        self._unsupported_models = 0
        self._cache: dict[str, LoadedModel] = {}
        self._registry_signature: tuple[int, int] | None = None

    def discover_models(self) -> list[ModelRecord]:
        with self._lock:
            self._refresh_registry()
            return list(self._records.values())

    def load_deployment_candidate(self) -> LoadedModel:
        with self._lock:
            self._refresh_registry()
            candidates = [record for record in self._records.values() if record.deployment_candidate]
            if self.selected_model_id:
                selected = self._records.get(self.selected_model_id)
                if selected is None:
                    if self._unsupported_models:
                        raise ModelVersionError("Selected model is incompatible with this API version")
                    raise ModelManagerError("Selected model is not present in the registry")
                candidates = [selected] if selected.deployment_candidate else []
            if not candidates:
                if self._unsupported_models:
                    raise ModelVersionError("Installed model is incompatible with this API version")
                raise ModelManagerError("No deployment candidate is installed")
            # Candidate loading is explicitly not activation; activated remains registry metadata.
            return self._load(candidates[0])

    def predict(self, text: str):
        with self._lock:
            loaded = self.load_deployment_candidate()
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Email text must not be empty")
            return loaded, loaded.predictor.predict_proba([text])[0]

    def health(self) -> dict[str, Any]:
        with self._lock:
            base = {
                "loaded_model": None, "model_version": None, "calibration": None,
                "deployment_candidate": False, "activated": False, "pipeline_sha": None,
                "registry_status": "unavailable", "registry_loaded": False,
                "artifact_found": False, "hash_verified": False, "model_available": False,
                "inference_ready": False, "reason_code": None,
            }
            try:
                self._refresh_registry()
                candidate = next((r for r in self._records.values()
                                  if r.deployment_candidate and (not self.selected_model_id or r.model_id == self.selected_model_id)), None)
                if candidate is None:
                    base["registry_status"] = "missing_candidate"
                    base["reason_code"] = "missing_deployment_candidate"
                    return base
                base.update({
                    "model_version": candidate.version,
                    "calibration": candidate.calibration,
                    "deployment_candidate": True,
                    "activated": candidate.activated,
                    "pipeline_sha": candidate.pipeline_hash,
                    "registry_loaded": True,
                    "artifact_found": self._artifact_path(candidate).exists(),
                })
                loaded = self._load(candidate)
                base.update({"loaded_model": loaded.record.model_id, "hash_verified": True,
                             "model_available": True, "inference_ready": True,
                             "registry_status": "ready"})
                return base
            except ModelManagerError as error:
                base["registry_status"] = error.code
                base["reason_code"] = error.code
                return base

    def _refresh_registry(self) -> None:
        if not self.registry_path.exists():
            raise ModelRegistryError("Model registry is missing")
        stat = self.registry_path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        if signature == self._registry_signature:
            return
        try:
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ModelRegistryError("Model registry must be an object")
            if payload.get("schema_version") != 1:
                raise ModelVersionError("Unsupported model registry schema")
            records = {}
            unsupported = 0
            entries = payload.get("models")
            if not isinstance(entries, list):
                raise ModelRegistryError("Model registry models entry is invalid")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ModelRegistryError("Model registry model entry is invalid")
                if entry.get("compatible_api_version") != self.compatible_api_version:
                    unsupported += 1
                    continue
                record = ModelRecord(
                    model_id=entry["model_id"], version=entry["version"],
                    artifact_path=self._resolve_path(entry["artifact_path"]),
                    vectorizer_path=self._resolve_path(entry["vectorizer_path"]),
                    feature_manifest_path=self._resolve_path(entry["feature_manifest_path"]),
                    pipeline_hash=entry["pipeline_hash"], vectorizer_hash=entry["vectorizer_hash"],
                    feature_manifest_hash=entry["feature_manifest_hash"], sha256=entry["sha256"],
                    calibration=entry["calibration"], threshold=float(entry["threshold"]),
                    deployment_candidate=bool(entry["deployment_candidate"]), activated=bool(entry["activated"]),
                    compatible_api_version=entry["compatible_api_version"],
                    training_timestamp=entry["training_timestamp"],
                )
                records[record.model_id] = record
            self._records = records
            self._unsupported_models = unsupported
            self._cache.clear()
            self._registry_signature = signature
        except KeyError as error:
            raise ModelRegistryError(f"Model registry entry missing field: {error.args[0]}") from None
        except json.JSONDecodeError:
            raise ModelRegistryError("Model registry is not valid JSON") from None
        except (TypeError, ValueError):
            raise ModelRegistryError("Model registry metadata is invalid") from None

    @staticmethod
    def _resolve_path(path: str | Path) -> Path:
        resolved = Path(path)
        return resolved if resolved.is_absolute() else PROJECT_ROOT / resolved

    def _artifact_path(self, record: ModelRecord) -> Path:
        return self.artifact_override or record.artifact_path

    def _load(self, record: ModelRecord) -> LoadedModel:
        artifact_path = self._artifact_path(record)
        cached = self._cache.get(record.model_id)
        if cached and _sha256(artifact_path) == record.sha256:
            return cached
        for path in (artifact_path, record.vectorizer_path, record.feature_manifest_path):
            if not path.exists():
                raise ModelManagerError("Approved model artifact is missing")
        if _sha256(artifact_path) != record.sha256:
            raise ModelIntegrityError("Pipeline hash does not match the signed registry hash")
        if _sha256(artifact_path) != record.pipeline_hash:
            raise ModelIntegrityError("Pipeline hash does not match pipeline_hash")
        if _sha256(record.vectorizer_path) != record.vectorizer_hash:
            raise ModelIntegrityError("Vectorizer hash does not match the signed registry hash")
        if _sha256(record.feature_manifest_path) != record.feature_manifest_hash:
            raise ModelIntegrityError("Feature manifest hash does not match the signed registry hash")
        try:
            bundle = joblib.load(artifact_path)
            if not isinstance(bundle, dict):
                raise ModelIntegrityError("Pipeline artifact metadata is invalid")
            if bundle.get("model_id") != record.model_id or bundle.get("activated") is not False:
                raise ModelIntegrityError("Pipeline metadata does not match inactive registry candidate")
            if float(bundle.get("decision_threshold")) != record.threshold:
                raise ModelIntegrityError("Pipeline threshold does not match registry")
            loaded = LoadedModel(record, bundle, __import__("time").perf_counter_ns())
        except ModelIntegrityError:
            raise
        except Exception as error:
            raise ModelIntegrityError(f"Pipeline could not be loaded: {type(error).__name__}") from None
        self._cache[record.model_id] = loaded
        return loaded
