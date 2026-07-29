from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_v1.py"
SPEC = importlib.util.spec_from_file_location("evaluate_v1", SCRIPT)
assert SPEC and SPEC.loader
evaluate_v1 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluate_v1
SPEC.loader.exec_module(evaluate_v1)


RAW_EMAIL = """From: sender@example.com
To: recipient@example.com
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <evaluation@example.com>
Subject: Project update

The project update is ready.
"""


def metadata(identifier: str, expected: str = "safe") -> dict[str, str]:
    return {
        "id": identifier,
        "label": expected,
        "source": "test-source",
        "campaign": f"campaign-{identifier}",
        "date": "2026-01-01",
        "expected_class": expected,
    }


def test_json_fixture_requires_and_accepts_ground_truth(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({**metadata("safe-1"), "raw_email": RAW_EMAIL}), encoding="utf-8")

    loaded = evaluate_v1.load_dataset([fixture])

    assert len(loaded.samples) == 1
    assert loaded.samples[0].id == "safe-1"
    assert loaded.samples[0].raw_email == RAW_EMAIL
    assert not loaded.rejected


def test_json_structured_fixture_uses_quick_paste_input_mode(tmp_path: Path) -> None:
    fixture = tmp_path / "structured.json"
    fixture.write_text(json.dumps({**metadata("structured-1"), "subject": "Project update", "body": "The update is ready."}), encoding="utf-8")

    loaded = evaluate_v1.load_dataset([fixture])

    assert len(loaded.samples) == 1
    assert loaded.samples[0].raw_email is None
    assert loaded.samples[0].request["input_mode"] == "quick_paste"


def test_binary_corpus_rows_are_rejected_without_invention(tmp_path: Path) -> None:
    fixture = tmp_path / "binary.csv"
    fixture.write_text("text,label,source\n\"hello\",0,legacy-source\n", encoding="utf-8")

    loaded = evaluate_v1.load_dataset([fixture])

    assert not loaded.samples
    assert len(loaded.rejected) == 1
    assert set((loaded.rejected[0]["missing_fields"])) >= {"id", "campaign", "date", "expected_class"}
    assert any("label=" in reason for reason in loaded.rejected[0]["invalid_reasons"])


def test_eml_directory_joins_sidecar_ground_truth(tmp_path: Path) -> None:
    email_path = tmp_path / "message.eml"
    email_path.write_text(RAW_EMAIL, encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps([{**metadata("eml-1"), "path": "message.eml"}]), encoding="utf-8")

    loaded = evaluate_v1.load_dataset([tmp_path])

    assert len(loaded.samples) == 1
    assert loaded.samples[0].id == "eml-1"
    assert loaded.samples[0].raw_email == RAW_EMAIL
    assert not loaded.rejected


def _row(expected: str, predicted: str, probability: float, rule_score: int = 0) -> dict:
    return {
        "id": f"{expected}-{predicted}-{probability}",
        "label": expected,
        "expected_class": expected,
        "source": "test-source",
        "campaign": "test-campaign",
        "date": "2026-01-01",
        "category": "Business Email",
        "predicted_class": predicted,
        "risk_score": round(probability * 100),
        "phishing_probability": probability,
        "ml_threshold": 0.5,
        "rule_score": rule_score,
        "decision_safety_state": "needs_review",
        "presentation_state": "needs_review",
        "safe_verdict_allowed": False,
        "triggered_indicators": [],
        "indicator_details": [],
        "evidence_families": [],
        "inference_latency_ms": 1.0,
        "total_processing_time_ms": 2.0,
        "rule_classification": "safe",
        "status": "ok",
        "error": None,
    }


def test_metrics_and_safety_review_are_binary_phishing_aware() -> None:
    rows = [
        _row("safe", "safe", 0.1),
        _row("suspicious", "phishing", 0.9, 80),
        _row("phishing", "safe", 0.2),
        _row("phishing", "phishing", 0.9, 80),
    ]

    metrics = evaluate_v1.calculate_metrics(rows)
    groups = evaluate_v1.error_rows(rows)

    binary = metrics["binary_phishing_vs_non_phishing"]
    assert binary["true_positive"] == 1
    assert binary["true_negative"] == 1
    assert binary["false_positive"] == 1
    assert binary["false_negative"] == 1
    assert binary["recall"] == 0.5
    assert len(groups["false_negatives"]) == 1
    assert "could_rules_have_caught_it" in groups["false_negatives"][0]
    assert "could_decision_safety_have_caught_it" in groups["false_negatives"][0]
