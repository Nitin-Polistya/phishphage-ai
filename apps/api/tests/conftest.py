"""Pytest configuration and fixtures."""

from __future__ import annotations

import os
import sys

import pytest

# Add the app directory to path so imports work correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.services import private_storage


@pytest.fixture(autouse=True)
def isolated_private_evaluation_root(tmp_path, monkeypatch):
    """Keep storage tests inside an isolated private evaluation root."""
    repository_root = tmp_path / 'repo'
    private_root = repository_root / 'services' / 'ml' / 'evaluation' / 'private'
    private_root.mkdir(parents=True)
    monkeypatch.setattr(private_storage, 'REPOSITORY_ROOT', repository_root)
    monkeypatch.setattr(private_storage, 'PRIVATE_EVALUATION_ROOT', private_root)
