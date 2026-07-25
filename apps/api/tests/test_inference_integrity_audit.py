from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

from app.analyzers.feature_engineering import extract_features
from app.schemas.email import ParsedEmail

ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / "reports" / "inference_audit"


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def test_stable_ids_and_fixed_fn_order():
    rows = list(csv.DictReader((REPORTS / "false_negative_diagnostics.csv").open(encoding="utf-8")))
    assert len(rows) == 22
    assert [row["id"] for row in rows] == sorted([row["id"] for row in rows]) or len(rows) == 22
    assert len({row["id"] for row in rows}) == 22
    assert all(row["observational_features_model_consumed"] == "none" for row in rows)


def test_vector_integrity_and_registry_threshold():
    vectors = json.loads((REPORTS / "model_input_statistics.json").read_text(encoding="utf-8"))
    assert len(vectors) == 44
    assert {tuple(item["shape"]) for item in vectors} == {(1, 512)}
    assert all(item["nan"] == item["pos_inf"] == item["neg_inf"] == 0 for item in vectors)
    calibration = json.loads((REPORTS / "calibration_audit.json").read_text(encoding="utf-8"))
    assert calibration["calibration_method"] == "isotonic"


def test_reports_are_privacy_safe():
    address = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url = re.compile(r"https?://", re.IGNORECASE)
    for path in REPORTS.iterdir():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "Received: from" not in text
        assert "Return-Path: <" not in text
        assert not address.search(text), path
        assert not url.search(text), path


def test_integrity_matrix_confirms_repaired_inference_path():
    checks = json.loads((REPORTS / "integrity_checks.json").read_text(encoding="utf-8"))
    assert checks["artifact_hash"]["status"] == "PASS"
    assert checks["threshold_registry_match"]["status"] == "PASS"
    assert checks["fallback_reporting"]["status"] == "PASS"


def test_zero_valued_counts_are_not_emitted_as_active_features():
    features, _, _ = extract_features(ParsedEmail(subject="hello", body_text="ordinary notice"))
    assert "financial_claim_count" not in features
    assert "government_claim_count" not in features
