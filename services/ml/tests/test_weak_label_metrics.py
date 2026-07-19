from __future__ import annotations

import numpy as np
import pandas as pd

from phishshield_ml.weak_label_experiments import error_summary, metrics, privacy_scan


def test_metrics_exposes_explicit_rates_and_confusion_matrix() -> None:
    report = metrics([0, 0, 1, 1], [0.1, 0.9, 0.2, 0.8], 0.5)
    assert report["accuracy"] == 0.5
    assert report["false_positive_rate"] == 0.5
    assert report["false_negative_rate"] == 0.5
    assert report["confusion_matrix"] == [[1, 1], [1, 1]]


def test_error_summary_is_aggregate_only() -> None:
    frame = pd.DataFrame({"text": ["Visit https://secret.example/a?token=x", "Routine project update"],
                          "label": [1, 0], "campaign_group": ["campaign-a", "campaign-b"]})
    summary = error_summary(frame, np.array([0, 1]), "fn")
    assert summary["count"] == 1
    assert summary["raw_content_included"] is False
    assert summary["addresses_or_urls_included"] is False
    assert "secret.example" not in str(summary)


def test_privacy_scan_covers_nested_reports(tmp_path) -> None:
    nested = tmp_path / "experiment"; nested.mkdir()
    (nested / "metrics.json").write_text('{"ok": true}', encoding="utf-8")
    result = privacy_scan(tmp_path)
    assert result == {"status": "passed", "files_scanned": 1, "violations": 0}

