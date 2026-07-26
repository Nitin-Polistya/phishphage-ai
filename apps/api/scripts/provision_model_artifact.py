"""Provision one approved model artifact without changing the model registry.

This script is deployment-only. It does not run during normal application
startup or local development. The URL and optional bearer token are supplied
by the deployment environment, never by an API request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
PROJECT_ROOT = Path(__file__).resolve().parents[3]
APPROVED_ROOT = (PROJECT_ROOT / "services" / "ml").resolve()


class ProvisioningError(RuntimeError):
    """A safe, user-facing provisioning failure."""


@dataclass(frozen=True)
class ArtifactConfig:
    source_url: str
    destination: Path
    expected_sha256: str
    max_bytes: int = DEFAULT_MAX_BYTES
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    bearer_token: str | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contained(path: Path, root: Path | None = None) -> Path:
    resolved_root = (root or APPROVED_ROOT).resolve()
    resolved = path if path.is_absolute() else PROJECT_ROOT / path
    resolved = resolved.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ProvisioningError("artifact destination is outside the approved model directory") from error
    return resolved


def _registry_hash(registry_path: Path, model_id: str) -> str:
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        matches = [item for item in payload["models"] if item["model_id"] == model_id]
        if len(matches) != 1 or not isinstance(matches[0].get("sha256"), str):
            raise KeyError
        expected = matches[0]["sha256"].lower()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ProvisioningError("approved model registry could not provide an expected hash") from error
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ProvisioningError("approved model registry hash is invalid")
    return expected


def build_config(environ: dict[str, str] | None = None) -> ArtifactConfig:
    values = environ or os.environ
    source_url = values.get("MODEL_ARTIFACT_URL", "").strip()
    if not source_url:
        raise ProvisioningError("MODEL_ARTIFACT_URL is required")
    if not source_url.startswith("https://"):
        raise ProvisioningError("MODEL_ARTIFACT_URL must use HTTPS")
    destination = _contained(Path(values.get(
        "ML_ARTIFACT_PATH",
        "services/ml/artifacts/phase_c_model_development_v1/deployment_candidate/fitted_pipeline.joblib",
    )))
    expected = values.get("ML_EXPECTED_SHA256", "").strip().lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        registry_path = _contained(Path(values.get("ML_REGISTRY_PATH", "services/ml/models/registry.json")))
        expected = _registry_hash(registry_path, values.get("ML_MODEL_ID", "phase-c-logistic-regression-v1"))
    try:
        max_bytes = int(values.get("MODEL_ARTIFACT_MAX_BYTES", str(DEFAULT_MAX_BYTES)))
        timeout = int(values.get("MODEL_ARTIFACT_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
    except ValueError as error:
        raise ProvisioningError("artifact size and timeout limits must be integers") from error
    if not 1 <= max_bytes <= 100 * 1024 * 1024 or not 1 <= timeout <= 300:
        raise ProvisioningError("artifact size or timeout limit is outside the safe range")
    return ArtifactConfig(source_url, destination, expected, max_bytes, timeout, values.get("MODEL_ARTIFACT_TOKEN"))


def provision_artifact(config: ArtifactConfig, opener: Callable[..., object] = urllib.request.urlopen) -> str:
    destination = _contained(config.destination)
    if destination.exists():
        raise ProvisioningError("refusing to overwrite an existing model artifact")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        request = urllib.request.Request(config.source_url, headers={
            "Authorization": f"Bearer {config.bearer_token}" if config.bearer_token else "",
            "User-Agent": "phishshield-model-provisioner/1",
        })
        if not config.bearer_token:
            request.remove_header("Authorization")
        with opener(request, timeout=config.timeout_seconds) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > config.max_bytes:
                raise ProvisioningError("model artifact exceeds the configured size limit")
            with tempfile.NamedTemporaryFile(prefix=".model-", suffix=".tmp", dir=destination.parent, delete=False) as handle:
                temporary_path = Path(handle.name)
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > config.max_bytes:
                        raise ProvisioningError("model artifact exceeds the configured size limit")
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        digest = _sha256(temporary_path)
        if digest != config.expected_sha256:
            raise ProvisioningError("model artifact hash does not match the approved registry hash")
        os.replace(temporary_path, destination)
        temporary_path = None
        return digest
    except (OSError, urllib.error.URLError, ValueError) as error:
        if isinstance(error, ProvisioningError):
            raise
        raise ProvisioningError("model artifact download failed") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="validate configuration without downloading")
    args = parser.parse_args()
    try:
        config = build_config()
        if args.dry_run:
            print(f"dry-run: destination is contained and expected hash is {config.expected_sha256}")
        else:
            print(f"provisioned approved model artifact with sha256={provision_artifact(config)}")
        return 0
    except ProvisioningError as error:
        print(f"provisioning failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
