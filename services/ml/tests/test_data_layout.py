from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = ROOT / "data"


def test_canonical_data_directories_exist_with_gitkeep() -> None:
    for name in ("raw", "interim", "processed", "external", "staging"):
        directory = DATA_ROOT / name
        assert directory.is_dir()
        assert (directory / ".gitkeep").is_file()


def test_external_directory_is_flat() -> None:
    assert not any(path.is_dir() for path in (DATA_ROOT / "external").iterdir())


def test_scripts_and_docs_do_not_reference_legacy_external_subdirectories() -> None:
    legacy_fragments = (
        '"external" / "raw"',
        '"external" / "interim"',
        '"external" / "processed"',
        "external/raw/",
        "external/interim/",
        "external/processed/",
    )
    checked = [
        *ROOT.joinpath("scripts").glob("*.py"),
        ROOT / "README.md",
        ROOT / "DATASET_ACQUISITION.md",
        DATA_ROOT / "README.md",
    ]
    for path in checked:
        text = path.read_text(encoding="utf-8")
        assert not any(fragment in text for fragment in legacy_fragments), path


def test_all_canonical_data_directories_are_git_ignored_except_gitkeep() -> None:
    ignore = ROOT.parents[1].joinpath(".gitignore").read_text(encoding="utf-8")
    for name in ("raw", "interim", "processed", "external", "staging"):
        assert f"services/ml/data/{name}/*" in ignore
        assert f"!services/ml/data/{name}/.gitkeep" in ignore
