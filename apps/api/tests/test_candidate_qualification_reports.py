from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports/candidate_qualification"
REGISTRY = ROOT / "services/ml/models/registry.json"


def test_qualification_reports_and_primary_exclusion():
    required = {
        "qualification_summary.md", "dataset_provenance.csv", "overlap_audit.json",
        "primary_model_comparison.csv", "grouped_performance.csv", "false_positive_analysis.csv",
        "false_negative_analysis.csv", "calibration_comparison.json", "multi_seed_stability.csv",
        "threshold_robustness.csv", "statistical_comparison.json", "diagnostic_challenge_set.csv",
        "qualification_gates.json", "artifact_manifest.json", "final_qualification_recommendation.md",
    }
    assert required <= {path.name for path in OUT.iterdir()}
    rows = list(csv.DictReader((OUT / "primary_model_comparison.csv").open(encoding="utf-8")))
    assert {row["model"] for row in rows} == {"approved", "linear_svm_sigmoid"}
    assert all(row["dataset"] == "spaphish_v5_independent" for row in rows)
    gates = json.loads((OUT / "qualification_gates.json").read_text(encoding="utf-8"))
    assert gates["challenge_excluded_from_primary"] is True
    assert gates["overall"] is False


def test_qualification_reports_are_privacy_safe_and_artifact_is_isolated():
    address = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url = re.compile(r"https?://", re.IGNORECASE)
    for path in OUT.iterdir():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not address.search(text), path
        assert not url.search(text), path
        assert str(ROOT) not in text, path
    manifest = json.loads((OUT / "artifact_manifest.json").read_text(encoding="utf-8"))
    assert manifest["production_registry_modified"] is False
    assert not str(ROOT / "services/ml/models") in manifest["artifact_relative_path"]


def test_reproducibility_and_false_negative_accounting():
    stability = list(csv.DictReader((OUT / "multi_seed_stability.csv").open(encoding="utf-8")))
    assert len(stability) == 5
    assert len({row["recall"] for row in stability}) == 1
    fn_rows = list(csv.DictReader((OUT / "false_negative_analysis.csv").open(encoding="utf-8")))
    fp_rows = list(csv.DictReader((OUT / "false_positive_analysis.csv").open(encoding="utf-8")))
    primary = {row["model"]: row for row in csv.DictReader((OUT / "primary_model_comparison.csv").open(encoding="utf-8"))}
    assert len(fn_rows) == int(primary["linear_svm_sigmoid"]["fn"]) + int(primary["linear_svm_sigmoid"]["tp"])
    assert len(fp_rows) == int(primary["linear_svm_sigmoid"]["fp"])
