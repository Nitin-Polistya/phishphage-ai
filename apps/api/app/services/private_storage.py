"""Repository-rooted paths for ignored local evaluation storage."""

from __future__ import annotations

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PRIVATE_EVALUATION_ROOT = (REPOSITORY_ROOT / 'services' / 'ml' / 'evaluation' / 'private').resolve()


def resolve_private_evaluation_path(configured_path: str | Path, *, error_message: str) -> Path:
    """Resolve a configured path and require it to remain under private storage."""
    candidate = Path(configured_path)
    if not candidate.is_absolute():
        candidate = REPOSITORY_ROOT / candidate
    resolved = candidate.resolve()
    if not resolved.is_relative_to(PRIVATE_EVALUATION_ROOT):
        raise ValueError(error_message)
    return resolved
