from __future__ import annotations

import json
import shutil
from pathlib import Path

import pandas as pd
import pytest

from phishshield_ml.corpus_inventory import (
    PROVENANCE_FIELDS,
    build_inventory,
    normalize_record,
    validate_corpus_boundaries,
)
from phishshield_ml.dataset_gaps import (
    build_gap_analysis,
    validate_source_manifest,
    validate_taxonomy,
)


ML_ROOT = Path(__file__).resolve().parents[1]


def _write_boundary(root: Path, relative: str, rows: list[dict]) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)


def _row(text: str, label: int, source: str, campaign: str, template: str, **extra: object) -> dict:
    return {
        "text": text, "label": label, "source": source, "language": "en",
        "provenance_type": "real_or_curated", "campaign_group": campaign,
        "template_group": template, "scenario": "project" if label == 0 else "credential",
        **extra,
    }


def test_inventory_is_deterministic_and_preserves_required_provenance(tmp_path: Path) -> None:
    relative = "data/processed/core.csv"
    _write_boundary(tmp_path, relative, [
        _row("Subject: Status\nProject meeting tomorrow.", 0, "source-a", "c1", "t1"),
        _row("Subject: Verify\nReview hxxps://example.invalid now.", 1, "source-b", "c2", "t2"),
    ])
    boundaries = {"development_pool": relative}
    first = build_inventory(tmp_path, boundaries)
    second = build_inventory(tmp_path, boundaries)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    normalized = normalize_record(_row("hello", 0, "source-a", "c1", "t1"), "train", 0)
    assert set(PROVENANCE_FIELDS).issubset(normalized)
    assert "text" not in normalized


def test_inventory_detects_exact_and_normalized_duplicates(tmp_path: Path) -> None:
    relative = "data/processed/core.csv"
    _write_boundary(tmp_path, relative, [
        _row("Invoice 123 at https://one.example", 1, "source-a", "c1", "t1"),
        _row("Invoice 456 at https://two.example", 1, "source-a", "c1", "t1"),
        _row("Invoice 456 at https://two.example", 1, "source-a", "c1", "t1"),
    ])
    inventory = build_inventory(tmp_path, {"development_pool": relative})
    assert inventory["duplicates"]["exact"]["duplicate_rows"] == 1
    assert inventory["duplicates"]["normalized"]["duplicate_rows"] == 2


def test_split_and_campaign_overlap_fail_loudly() -> None:
    train = normalize_record(_row("first text", 0, "a", "same-campaign", "t1"), "train", 0)
    validation = normalize_record(_row("second text", 0, "b", "same-campaign", "t2"), "validation", 0)
    with pytest.raises(ValueError, match="campaign_group overlap"):
        validate_corpus_boundaries([train, validation])


def test_normalized_duplicate_overlap_fails_loudly() -> None:
    train = normalize_record(_row("Invoice 123", 1, "a", "c1", "t1"), "train", 0)
    test = normalize_record(_row("Invoice 456", 1, "b", "c2", "t2"), "test", 0)
    with pytest.raises(ValueError, match="normalized_content_hash overlap"):
        validate_corpus_boundaries([train, test])


def test_semantic_near_duplicate_overlap_fails_loudly() -> None:
    train = normalize_record(_row("Please verify account access now", 1, "a", "c1", "t1"), "train", 0)
    test = normalize_record(_row("Please verify account access now!", 1, "b", "c2", "t2"), "test", 0)
    with pytest.raises(ValueError, match="semantic near-duplicate overlap"):
        validate_corpus_boundaries([train, test])


def test_external_evaluation_isolation_fails_loudly() -> None:
    record = normalize_record(
        _row("external only", 1, "zenodo-validation-13474746", "c1", "t1", external_evaluation_only=True),
        "train", 0,
    )
    with pytest.raises(ValueError, match="external evaluation row entered train"):
        validate_corpus_boundaries([record])


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (_row("Spanish", 0, "source", "c1", "t1", language="es"), "Spanish row"),
        (_row("spam", 1, "apache_spamassassin_spam", "c1", "t1"), "generic SpamAssassin spam"),
        (_row("url", 1, "OpenPhish", "c1", "t1"), "URL reputation data"),
    ],
)
def test_primary_language_and_label_role_rules_fail_loudly(row: dict, message: str) -> None:
    record = normalize_record(row, "train", 0)
    with pytest.raises(ValueError, match=message):
        validate_corpus_boundaries([record])


def test_synthetic_and_source_dominance_are_reported() -> None:
    records = [
        normalize_record(_row(f"message {index}", index % 2, "one-source", f"c{index}", f"t{index}", provenance_type="synthetic_generated"), "development_pool", index)
        for index in range(5)
    ]
    result = validate_corpus_boundaries(records, strict=False)
    assert any("synthetic dominance" in warning for warning in result["warnings"])
    assert any("source dominance" in warning for warning in result["warnings"])


def test_taxonomy_is_valid() -> None:
    taxonomy = json.loads((ML_ROOT / "config/dataset_expansion_taxonomy.json").read_text(encoding="utf-8"))
    validate_taxonomy(taxonomy)
    identifiers = {category["id"] for category in taxonomy["categories"]}
    assert {"legit_workplace_collaboration", "phish_microsoft_365", "phish_attachment_delivered"} <= identifiers


def test_gap_calculation_uses_real_counts_and_campaigns(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    shutil.copyfile(ML_ROOT / "config/dataset_expansion_taxonomy.json", tmp_path / "config/dataset_expansion_taxonomy.json")
    _write_boundary(tmp_path, "data/processed/english_core_v3.csv", [
        _row("project one", 0, "source-a", "c1", "t1", scenario="project"),
        _row("project two", 0, "source-b", "c2", "t2", scenario="project", provenance_type="synthetic_generated"),
    ])
    result = build_gap_analysis(tmp_path)
    category = next(item for item in result["categories"] if item["category_id"] == "legit_workplace_collaboration")
    assert category["current_sample_count"] == 2
    assert category["current_real_sample_count"] == 1
    assert category["synthetic_count"] == 1
    assert category["independent_campaign_count"] == 2
    assert category["sample_deficit"] == category["target_real_sample_count"] - 1


def test_unknown_license_requires_manual_review() -> None:
    manifest = json.loads((ML_ROOT / "config/dataset_source_manifest.example.json").read_text(encoding="utf-8"))
    validate_source_manifest(manifest)
    manifest["license"]["status"] = "approved"
    with pytest.raises(ValueError, match="Unknown licenses require manual review"):
        validate_source_manifest(manifest)
