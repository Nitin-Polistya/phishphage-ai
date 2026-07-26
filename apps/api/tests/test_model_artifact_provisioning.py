from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "provision_model_artifact.py"
SPEC = importlib.util.spec_from_file_location("provision_model_artifact", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def _config(tmp_path: Path, expected: str, **kwargs):
    module.APPROVED_ROOT = tmp_path
    return module.ArtifactConfig(
        source_url="https://artifact.invalid/model.joblib",
        destination=tmp_path / "model.joblib",
        expected_sha256=expected,
        **kwargs,
    )


class Response:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _size):
        payload, self.payload = self.payload, b""
        return payload


def test_success_is_atomic_and_hash_verified(tmp_path: Path):
    payload = b"synthetic model bytes"
    digest = hashlib.sha256(payload).hexdigest()
    result = module.provision_artifact(_config(tmp_path, digest), opener=lambda *_args, **_kwargs: Response(payload))
    assert result == digest
    assert (tmp_path / "model.joblib").read_bytes() == payload
    assert not list(tmp_path.glob(".model-*.tmp"))


def test_hash_mismatch_cleans_temporary_file(tmp_path: Path):
    with pytest.raises(module.ProvisioningError, match="hash"):
        module.provision_artifact(_config(tmp_path, "0" * 64), opener=lambda *_args, **_kwargs: Response(b"wrong"))
    assert not (tmp_path / "model.joblib").exists()
    assert not list(tmp_path.glob(".model-*.tmp"))


def test_size_limit_and_existing_destination_are_safe(tmp_path: Path):
    payload = b"too large"
    digest = hashlib.sha256(payload).hexdigest()
    with pytest.raises(module.ProvisioningError, match="size"):
        module.provision_artifact(_config(tmp_path, digest, max_bytes=2), opener=lambda *_args, **_kwargs: Response(payload))
    destination = tmp_path / "model.joblib"
    destination.write_bytes(b"keep")
    with pytest.raises(module.ProvisioningError, match="overwrite"):
        module.provision_artifact(_config(tmp_path, digest), opener=lambda *_args, **_kwargs: Response(payload))


def test_destination_containment_is_enforced(tmp_path: Path):
    with pytest.raises(module.ProvisioningError, match="outside"):
        module._contained(Path("C:/outside/model.joblib"), tmp_path)
