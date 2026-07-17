from __future__ import annotations

from pathlib import Path

import pandas as pd

from phishshield_ml.config import MLConfig
from phishshield_ml.generalization import build_generalization_candidates, prepare_generalization_corpus
from phishshield_ml.security_features import FEATURE_NAMES, extract_security_indicators


def _baseline(path: Path) -> Path:
    rows = []
    for label, prefix in ((0, "legitimate"), (1, "phishing")):
        for group in range(10):
            for variant in range(2):
                rows.append({
                    "text": f"{prefix} campaign {group} variant {variant} has sufficiently descriptive English words",
                    "label": label,
                    "language": "en",
                    "template_group": f"{prefix}-{group}",
                    "source": "fixture",
                    "provenance_type": "synthetic",
                    "scenario": f"scenario-{group}",
                })
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_structured_indicators_detect_security_concepts() -> None:
    text = """From: Support <notice@example.com>
Reply-To: agent@different.test
Subject: Urgent account suspension
<html><a href="https://xn--secure-9za.zip/login">example.com</a></html>
Confirm your password immediately. Attachment: update.scr
"""
    values = dict(zip(FEATURE_NAMES, extract_security_indicators(text), strict=True))
    assert values["url_count"] > 0
    assert values["punycode_domain"] == 1
    assert values["suspicious_tld"] == 1
    assert values["sender_reply_to_mismatch"] == 1
    assert values["html_link_text_mismatch"] == 1
    assert values["urgency_score"] > 0
    assert values["credential_language_score"] > 0
    assert values["risky_attachment_indicator"] == 1


def test_candidate_matrix_covers_features_and_models() -> None:
    names = set(build_generalization_candidates(MLConfig(max_features=100)))
    assert len(names) == 6
    assert all(any(name.startswith(prefix) for name in names) for prefix in ("A_", "B_", "C_"))
    assert sum("logistic_regression" in name for name in names) == 3
    assert sum("calibrated_linear_svc" in name for name in names) == 3


def test_preparation_reserves_grouped_diagnostic_without_exact_leakage(tmp_path: Path) -> None:
    output = tmp_path / "core_v3.csv"
    diagnostic = tmp_path / "diagnostic.csv"
    audit_path = tmp_path / "audit.json"
    audit = prepare_generalization_corpus(_baseline(tmp_path / "baseline.csv"), output, diagnostic, audit_path)
    development = pd.read_csv(output)
    held_out = pd.read_csv(diagnostic)
    assert set(development["text"]).isdisjoint(held_out["text"])
    assert audit["exact_diagnostic_overlap"] == 0
    assert audit["selection_uses_grouped_diagnostic"] is True
    assert audit["synthetic_percentage"] == 100.0
