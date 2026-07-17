"""Evaluate the provisioned model and fusion path on tracked safe fixtures."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[3]
for path in (PROJECT_ROOT / "apps" / "api", PROJECT_ROOT / "services" / "ml" / "src", PROJECT_ROOT / "services" / "ml" / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.main import app
from app.services.analysis_pipeline import pipeline
from fixtures.safe_email_cases import ALL_CASES


def main() -> int:
    pipeline.model_path = PROJECT_ROOT / "services" / "ml" / "models" / "phishshield_model.joblib"
    pipeline.ml_required = True
    pipeline._ml_service = None  # type: ignore[protected-access]
    client = TestClient(app)
    rows = []
    confusion = Counter()
    scenario_counts: dict[str, Counter] = defaultdict(Counter)
    for case in ALL_CASES:
        payload = {key: value for key, value in case.items() if key in {"input_mode", "raw_email", "subject", "body"}}
        response = client.post("/api/v1/analysis/preview", json=payload)
        if response.status_code != 200:
            raise RuntimeError(f"{case['id']} returned HTTP {response.status_code}")
        data = response.json()
        ml_prediction = data["ml_analysis"]["prediction"]
        expected = 1 if case["category"] == "phishing" else 0 if case["category"] in {"legitimate", "hard_negative"} else None
        if expected is not None:
            confusion[(expected, int(ml_prediction == "phishing"))] += 1
        scenario = case.get("scenario", case["category"])
        scenario_counts[scenario][ml_prediction] += 1
        rows.append({
            "id": case["id"], "category": case["category"], "scenario": scenario,
            "ml_prediction": ml_prediction,
            "phishing_probability": round(float(data["ml_analysis"]["phishing_probability"]), 6),
            "rule_classification": data["rule_analysis"]["classification"],
            "fused_classification": data["decision"]["classification"],
            "engine_agreement": data["engine_agreement"],
            "analysis_completeness": data["analysis_completeness"]["state"],
        })
    tn, fp, fn, tp = confusion[(0, 0)], confusion[(0, 1)], confusion[(1, 0)], confusion[(1, 1)]
    payload = {
        "raw_bodies_included": False,
        "fixture_count": len(rows),
        "category_counts": dict(Counter(row["category"] for row in rows)),
        "ml_confusion_matrix": [[tn, fp], [fn, tp]],
        "ml_false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "ml_false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "rule_ml_disagreements": sum(row["engine_agreement"] == "disagreement" for row in rows),
        "scenario_predictions": {scenario: dict(counts) for scenario, counts in sorted(scenario_counts.items())},
        "examples": rows,
    }
    output = PROJECT_ROOT / "services" / "ml" / "reports" / "fixture_evaluation.json"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({key: payload[key] for key in ("fixture_count", "category_counts", "ml_confusion_matrix", "ml_false_positive_rate", "ml_false_negative_rate", "rule_ml_disagreements")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
