from __future__ import annotations

from pathlib import Path

import pytest

from app.core.settings import Settings


def test_production_cors_normalizes_exact_origins_and_rejects_localhost():
    settings = Settings(ENVIRONMENT="production", CORS_ORIGINS="https://demo.example, https://demo.example/")
    assert settings.cors_origins == ["https://demo.example"]
    with pytest.raises(ValueError, match="localhost"):
        Settings(ENVIRONMENT="production", CORS_ORIGINS="http://localhost:3000")


def test_wildcard_cors_is_rejected():
    with pytest.raises(ValueError, match="wildcard"):
        Settings(CORS_ORIGINS="https://demo.example, *")


def test_production_defaults_keep_ml_explicit_and_proxy_empty():
    settings = Settings(ENVIRONMENT="production", CORS_ORIGINS="https://demo.example")
    assert settings.ml_required is False
    assert settings.trusted_proxy_ips == []
    assert settings.rate_limit_enabled is True


def test_render_manifest_has_no_secret_values_or_auto_deploy():
    manifest = Path(__file__).parents[3] / "render.yaml"
    content = manifest.read_text(encoding="utf-8")
    assert "autoDeploy: false" in content
    assert "sync: false" in content
    assert "private-artifact" not in content


def test_dockerfile_uses_non_root_and_does_not_copy_reports_or_datasets():
    dockerfile = (Path(__file__).parents[3] / "apps/api/Dockerfile").read_text(encoding="utf-8")
    assert "USER appuser" in dockerfile
    assert "--workers ${WEB_CONCURRENCY:-1}" in dockerfile
    assert "COPY services/ml/reports" not in dockerfile
    assert "COPY services/ml/data" not in dockerfile
