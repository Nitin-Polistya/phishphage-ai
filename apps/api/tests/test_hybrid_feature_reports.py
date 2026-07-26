from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports/hybrid_features"
sys.path.insert(0, str(ROOT / "apps/api/scripts"))
from run_hybrid_feature_experiments import gated_features


def test_hybrid_deliverables_and_ablation_coverage():
    required = {
        "current_feature_space.md", "engineered_feature_ranking.csv", "feature_group_results.csv",
        "ablation_summary.csv", "hybrid_candidate.md", "feature_selection.md",
        "precision_recall_tradeoff.csv", "recommendation.md", "false_positive_root_causes.csv",
        "feature_semantic_audit.csv", "gated_feature_definitions.json", "subgroup_performance.csv",
        "challenge_set_comparison.csv", "calibration_comparison.json", "acceptance_gates.json",
    }
    assert required <= {path.name for path in OUT.iterdir()}
    rows = list(csv.DictReader((OUT / "feature_group_results.csv").open(encoding="utf-8")))
    assert {row["feature_set"] for row in rows} == {"text_only", "authentication", "organization", "financial", "credential", "urgency", "infrastructure", "best5", "best10", "all", "gated_organization", "gated_best5", "gated_all"}
    assert {row["dataset"] for row in rows} == {"independent", "challenge_22", "hard_negatives"}


def test_hybrid_reports_are_privacy_safe():
    address = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url = re.compile(r"https?://", re.IGNORECASE)
    for path in OUT.iterdir():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not address.search(text), path
        assert not url.search(text), path


def test_gated_feature_truth_tables():
    assert "government_claim" not in gated_features({"government_claim": 1})
    assert "government_claim_unofficial_sender_and_link" in gated_features({"government_claim": 1, "government_domain_mismatch": 1, "unrelated_link_domain_present": 1})
    assert "financial_claim_with_urgent_action" in gated_features({"financial_claim": 1, "urgent_action": 1})
    assert "financial_claim" not in gated_features({"financial_claim": 1})
