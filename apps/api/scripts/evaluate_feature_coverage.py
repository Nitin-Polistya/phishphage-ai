"""Evaluate the new observational feature-engineering layer across a representative set of phishing and legitimate emails."""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from app.analyzers.feature_engineering import extract_features

import sys

# Setup paths to allow importing from apps/api
API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.services.analysis_pipeline import AnalysisPipeline

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def get_stable_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def load_sample_emails(
    phishing_dir: Path, safe_dir: Path, metadata_path: Path, n: int = 50
) -> list[tuple[Path, str]]:
    """Sample balanced emails for evaluation."""
    phishing_candidates: list[tuple[Path, str]] = []
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                meta = json.loads(line)
                # The metadata uses candidate_id, files are in phishing_dir as {candidate_id}.eml
                cid = meta.get("candidate_id")
                if cid:
                    full_path = phishing_dir / f"{cid}.eml"
                    if full_path.exists():
                        phishing_candidates.append((full_path, "phishing"))

    # Sample phishing
    random.seed(42)
    phishing_sample = random.sample(
        phishing_candidates, min(len(phishing_candidates), n)
    )

    # Sample safe emails (hard negatives/legit)
    safe_candidates: list[tuple[Path, str]] = []
    if safe_dir.exists():
        for file in safe_dir.rglob("*.eml"):
            safe_candidates.append((file, "safe"))

    safe_sample = random.sample(safe_candidates, min(len(safe_candidates), n))

    return phishing_sample + safe_sample


def evaluate() -> None:
    # Configuration
    phishing_raw_dir = (
        PROJECT_ROOT
        / "services"
        / "ml"
        / "data"
        / "staging"
        / "phishing_pot_pilot_001"
        / "raw"
    )
    phishing_meta = (
        PROJECT_ROOT
        / "services"
        / "ml"
        / "data"
        / "staging"
        / "phishing_pot_pilot_001"
        / "validation"
        / "selected_metadata.jsonl"
    )
    safe_raw_dir = (
        PROJECT_ROOT
        / "services"
        / "ml"
        / "data"
        / "external"
        / "phishing_pot"
        / "repository"
        / "email"
    )

    report_dir = PROJECT_ROOT / "reports" / "feature_coverage"
    report_dir.mkdir(parents=True, exist_ok=True)

    pipeline = AnalysisPipeline()

    samples = load_sample_emails(phishing_raw_dir, safe_raw_dir, phishing_meta)
    print(f"Evaluating {len(samples)} samples...")

    results: list[dict[str, Any]] = []

    for path, label in samples:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw_email = f.read()

            # Use pipeline to get parsed email and ML results
            response = pipeline.run(raw_email)
            parsed_email = response.parser

            # Extract features using the observational layer
            features, _, _ = extract_features(parsed_email)

            # Language (deterministic detection if available, otherwise 'en')
            language = "en"

            results.append(
                {
                    "id": get_stable_id(raw_email),
                    "label": label,
                    "language": language,
                    "ml_probability": response.ml_phishing_probability or 0.0,
                    "classification": response.decision.classification.value,
                    "features": features,
                    "auth_status": response.authentication_evidence_status,
                    "source": (
                        "phishing_pot" if "phishing_pot" in str(path) else "other"
                    ),
                }
            )
        except Exception as e:
            print(f"Error processing {path}: {e}")

    # --- METRICS CALCULATION ---

    phishing_res = [r for r in results if r["label"] == "phishing"]
    safe_res = [r for r in results if r["label"] == "safe"]

    def avg_features(res_list: list[dict[str, Any]]) -> float:
        if not res_list:
            return 0.0
        return sum(len(r["features"]) for r in res_list) / len(res_list)

    metrics: dict[str, float] = {
        "avg_features_phishing": avg_features(phishing_res),
        "avg_features_safe": avg_features(safe_res),
        "total_samples": float(len(results)),
        "phishing_count": float(len(phishing_res)),
        "safe_count": float(len(safe_res)),
    }

    # Feature Prevalence
    all_feature_names: set[str] = {
        str(feat) for r in results for feat in r["features"].keys()
    }
    prevalence: dict[str, dict[str, float]] = {}
    for feat in all_feature_names:
        phish_count = sum(1 for r in phishing_res if feat in r["features"])
        safe_count = sum(1 for r in safe_res if feat in r["features"])
        prevalence[feat] = {
            "phishing_pct": (
                (phish_count / len(phishing_res) * 100) if phishing_res else 0.0
            ),
            "safe_pct": (
                (safe_count / len(safe_res) * 100) if safe_res else 0.0
            ),
            "phishing_count": float(phish_count),
            "safe_count": float(safe_count),
        }

    # --- FALSE NEGATIVE / POSITIVE REVIEW (Threshold 0.5) ---
    fns: list[dict[str, Any]] = []
    fps: list[dict[str, Any]] = []
    for r in results:
        prob = r["ml_probability"]
        label = r["label"]

        if label == "phishing" and prob < 0.5:
            fns.append(r)
        elif label == "safe" and prob >= 0.5:
            fps.append(r)

    # --- OUTPUT ARTIFACTS ---

    # 1. Summary JSON
    with open(report_dir / "feature_coverage_summary.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # 2. Feature Prevalence CSV
    with open(report_dir / "feature_prevalence.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["feature", "phishing_pct", "safe_pct", "phishing_count", "safe_count"]
        )
        for feat, vals in prevalence.items():
            writer.writerow(
                [
                    feat,
                    vals["phishing_pct"],
                    vals["safe_pct"],
                    int(vals["phishing_count"]),
                    int(vals["safe_count"]),
                ]
            )

    # 3. FN Coverage CSV
    with open(report_dir / "false_negative_coverage.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "probability", "language", "feature_count", "features"])
        for fn in fns:
            writer.writerow(
                [
                    fn["id"],
                    fn["ml_probability"],
                    fn["language"],
                    len(fn["features"]),
                    ",".join(fn["features"].keys()),
                ]
            )

    # 4. FP Coverage CSV
    with open(report_dir / "false_positive_coverage.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "probability", "language", "feature_count", "features"])
        for fp in fps:
            writer.writerow(
                [
                    fp["id"],
                    fp["ml_probability"],
                    fp["language"],
                    len(fp["features"]),
                    ",".join(fp["features"].keys()),
                ]
            )

    # 5. Report Markdown
    with open(report_dir / "feature_coverage_report.md", "w") as f:
        f.write("# Feature Coverage Evaluation Report\n\n")
        f.write("## 1. Evaluation Summary\n")
        f.write(f"- Total samples evaluated: {metrics['total_samples']}\n")
        f.write(f"- Phishing samples: {metrics['phishing_count']}\n")
        f.write(f"- Safe samples: {metrics['safe_count']}\n")
        f.write(f"- Avg features (Phishing): {metrics['avg_features_phishing']:.2f}\n")
        f.write(f"- Avg features (Safe): {metrics['avg_features_safe']:.2f}\n\n")

        f.write("## 2. Feature Prevalence\n")
        f.write("| Feature | Phishing % | Safe % | Phishing Count | Safe Count |\n")
        f.write("|---|---|---|---|---|\n")
        for feat, vals in sorted(
            prevalence.items(), key=lambda x: x[1]["phishing_pct"], reverse=True
        ):
            f.write(
                f"| {feat} | {vals['phishing_pct']:.1f}% | {vals['safe_pct']:.1f}% | {int(vals['phishing_count'])} | {int(vals['safe_count'])} |\n"
            )

        f.write("\n## 3. False Negative Analysis (Prob < 0.5)\n")
        f.write(f"- Total FNs: {len(fns)}\n")
        if fns:
            f.write("\n### Common Patterns in FNs\n")
            fn_features = Counter(
                [feat for fn in fns for feat in fn["features"].keys()]
            )
            for feat, count in fn_features.most_common(5):
                f.write(f"- {feat}: {count} samples\n")

        f.write("\n## 4. False Positive Analysis (Prob >= 0.5)\n")
        f.write(f"- Total FPs: {len(fps)}\n")
        if fps:
            f.write("\n### Common Patterns in FPs\n")
            fp_features = Counter(
                [feat for fp in fps for feat in fp["features"].keys()]
            )
            for feat, count in fp_features.most_common(5):
                f.write(f"- {feat}: {count} samples\n")

    print(f"Evaluation complete. Reports generated in {report_dir}")


if __name__ == "__main__":
    evaluate()
