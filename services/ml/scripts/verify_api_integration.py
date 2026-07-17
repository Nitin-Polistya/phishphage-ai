"""Run non-mocked model inference through the existing FastAPI preview route."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[3]
API_ROOT = PROJECT_ROOT / "apps" / "api"
ML_SRC = PROJECT_ROOT / "services" / "ml" / "src"
for path in (API_ROOT, ML_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.main import app
from app.services.analysis_pipeline import pipeline


EXAMPLES = {
    "legitimate_project": "From: lead@example.com\nTo: team@example.com\nSubject: Sprint review\n\nPlease review the project notes before Friday's planning meeting.",
    "customer_support": "From: support@example.com\nTo: customer@example.com\nSubject: Ticket update\n\nWe received your support request. Reply with the ticket number if you need more help.",
    "credential_phishing": "From: alerts@untrusted.invalid\nTo: user@example.com\nSubject: Urgent credential verification\n\nVerify your password immediately at https://login-check.invalid/account or access will be blocked.",
    "fake_invoice": "From: billing@untrusted.invalid\nTo: accounts@example.com\nSubject: Overdue invoice\n\nOpen the attached invoice and send payment today to avoid a penalty.",
    "delivery_scam": "From: parcel@untrusted.invalid\nTo: user@example.com\nSubject: Delivery failed\n\nYour parcel is held. Pay the small redelivery fee at https://parcel-fee.invalid/claim.",
    "account_suspension": "From: security@untrusted.invalid\nTo: user@example.com\nSubject: Account suspension warning\n\nYour account will be suspended today unless you confirm your login details now.",
    "legitimate_security": "From: it@example.com\nTo: staff@example.com\nSubject: Security training reminder\n\nOur scheduled security workshop covers account recovery and password-manager use. No password or login response is required.",
    "rule_ml_disagreement": "From: newsletter@example.com\nTo: member@example.com\nSubject: Account security digest\n\nThis month's educational digest explains password safety and common credential phishing tactics.",
}


def main() -> int:
    model_path = PROJECT_ROOT / "services" / "ml" / "models" / "phishshield_model.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"Provisioned model not found: {model_path}")
    pipeline.model_path = model_path
    pipeline.ml_required = True
    pipeline._ml_service = None  # type: ignore[protected-access]
    client = TestClient(app)
    results = []
    for name, raw_email in EXAMPLES.items():
        response = client.post("/api/v1/analysis/preview", json={"raw_email": raw_email})
        if response.status_code != 200:
            raise RuntimeError(f"{name} returned HTTP {response.status_code}: {response.text}")
        data = response.json()
        ml = data["ml_analysis"]
        if ml["status"] != "available":
            raise RuntimeError(f"{name} used an ML-unavailable fallback")
        phishing_probability = float(ml["phishing_probability"])
        legitimate_probability = float(ml["legitimate_probability"])
        if not 0.0 <= phishing_probability <= 1.0 or not 0.0 <= legitimate_probability <= 1.0:
            raise RuntimeError(f"{name} returned invalid probabilities")
        if abs((phishing_probability + legitimate_probability) - 1.0) > 1e-6:
            raise RuntimeError(f"{name} probabilities do not sum to one")
        rule_class = data["rule_analysis"]["classification"]
        ml_class = "phishing" if ml["prediction"] == "phishing" else "safe"
        results.append({
            "example": name,
            "http_status": response.status_code,
            "ml_status": ml["status"],
            "ml_prediction": ml["prediction"],
            "phishing_probability": round(phishing_probability, 6),
            "legitimate_probability": round(legitimate_probability, 6),
            "probabilities_sum_to_one": True,
            "rule_classification": rule_class,
            "rule_risk_score": data["rule_analysis"]["risk_score"],
            "rule_ml_agree": rule_class == ml_class,
            "fused_classification": data["decision"]["classification"],
            "fused_risk_score": data["decision"]["risk_score"],
        })

    payload = {
        "route": "POST /api/v1/analysis/preview",
        "mocked": False,
        "ml_required": True,
        "model_path": "services/ml/models/phishshield_model.joblib",
        "all_ml_available": all(row["ml_status"] == "available" for row in results),
        "rule_only_fallback_used": False,
        "examples": results,
    }
    output = PROJECT_ROOT / "services" / "ml" / "reports" / "api_verification.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
