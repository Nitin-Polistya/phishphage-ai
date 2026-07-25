from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports/model_improvement"


def test_model_improvement_deliverables_exist_and_cover_experiments():
    required = {
        "current_training.md", "false_negative_analysis.csv", "feature_importance.csv",
        "threshold_analysis.csv", "experiment_summary.csv", "calibration_report.md",
        "final_recommendation.md",
    }
    assert required <= {path.name for path in OUT.iterdir()}
    rows = list(csv.DictReader((OUT / "experiment_summary.csv").open(encoding="utf-8")))
    assert {row["experiment"] for row in rows} >= {
        "baseline_lr_c1.0", "lr_balanced_c0.25", "lr_balanced_c2.0",
        "lr_balanced_c4.0", "linear_svm_sigmoid", "random_forest_sigmoid",
    }
    assert {row["evaluation"] for row in rows} >= {"phishing_22", "grouped_diagnostic", "external_evaluation"}


def test_false_negative_and_threshold_reports_are_privacy_safe():
    fn_rows = list(csv.DictReader((OUT / "false_negative_analysis.csv").open(encoding="utf-8")))
    assert len(fn_rows) == 22
    threshold_rows = list(csv.DictReader((OUT / "threshold_analysis.csv").open(encoding="utf-8")))
    assert [row["threshold"] for row in threshold_rows] == ["0.3", "0.35", "0.4", "0.45", "0.5", "0.55", "0.6"]
    address = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    url = re.compile(r"https?://", re.IGNORECASE)
    for path in OUT.iterdir():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not address.search(text), path
        assert not url.search(text), path
