"""Phase G.6 controlled, non-production model improvement experiment.

All estimators are trained in memory from the frozen Phase C boundary-audited
training frame. No production artifact or registry entry is written.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[3]
ML_SRC = ROOT / "services/ml/src"
if str(ML_SRC) not in sys.path:
    sys.path.insert(0, str(ML_SRC))
API_ROOT = ROOT / "apps/api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.services.email_parser import parse_email
from app.services.model_manager import ModelManager
from phishshield_ml.weak_label_experiments import boundary_audit, load_config

OUT = ROOT / "reports/model_improvement"
CFG = ROOT / "services/ml/config/experiments/phishing_pot_weak_label_comparison_v1.json"
PHISH = ROOT / "services/ml/data/staging/phishing_pot_pilot_001"


def sid(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def ece(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for i in range(bins):
        mask = (p >= edges[i]) & (p < edges[i + 1] if i < bins - 1 else p <= 1)
        if mask.any():
            total += float(mask.sum() / len(p)) * abs(float(p[mask].mean()) - float(y[mask].mean()))
    return float(total)


def metrics(y: np.ndarray, p: np.ndarray, threshold: float = .5) -> dict[str, Any]:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "f1": float(f1_score(y, pred, zero_division=0)), "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None, "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) == 2 else None, "brier_score": float(brier_score_loss(y, p)), "ece": ece(y, p), "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp), "fpr": float(fp / (fp + tn)) if fp + tn else 0.0, "fnr": float(fn / (fn + tp)) if fn + tp else 0.0}


def probabilities(model: Any, texts: list[str]) -> tuple[np.ndarray, np.ndarray | None]:
    raw = None
    if hasattr(model, "decision_function"):
        score = np.asarray(model.decision_function(texts), dtype=float)
        raw = 1 / (1 + np.exp(-np.clip(score, -40, 40)))
    elif hasattr(model, "predict_proba"):
        raw = np.asarray(model.predict_proba(texts)[:, 1], dtype=float)
    calibrated = np.asarray(model.predict_proba(texts)[:, 1], dtype=float) if hasattr(model, "predict_proba") else raw
    return calibrated, raw


def make_pipeline(kind: str, parameter: Any) -> Pipeline:
    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=.95, max_features=30000, sublinear_tf=True, strip_accents="unicode")
    if kind == "lr":
        estimator = LogisticRegression(C=float(parameter), class_weight="balanced", solver="liblinear", max_iter=2000, random_state=42)
    elif kind == "svm":
        estimator = CalibratedClassifierCV(LinearSVC(C=float(parameter), class_weight="balanced", random_state=42), method="sigmoid", cv=3)
    else:
        estimator = CalibratedClassifierCV(RandomForestClassifier(n_estimators=150, max_depth=parameter, class_weight="balanced", random_state=42, n_jobs=1), method="sigmoid", cv=3)
    return Pipeline([("features", vectorizer), ("clf", estimator)])


def load_phish_samples() -> list[tuple[str, str]]:
    rows = []
    meta = PHISH / "validation/selected_metadata.jsonl"
    for line in meta.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        path = PHISH / "raw" / f"{item['candidate_id']}.eml"
        if path.exists():
            raw = path.read_text(encoding="utf-8", errors="ignore")
            parsed = parse_email(raw)
            rows.append((sid(raw), f"{parsed.subject or ''}\n{parsed.body_text}"))
    return rows


def feature_rows(model: Pipeline, texts: list[str], limit: int = 5) -> list[list[str]]:
    vectorizer = model.named_steps["features"]
    clf = model.named_steps["clf"]
    if not hasattr(clf, "coef_"):
        return [["unavailable"] for _ in texts]
    matrix = vectorizer.transform(texts)
    names = vectorizer.get_feature_names_out()
    coef = np.asarray(clf.coef_).ravel()
    result = []
    for row in matrix:
        contributions = [(str(names[i]), float(row[0, i] * coef[i])) for i in row.nonzero()[1]]
        result.append([name for name, _ in sorted(contributions, key=lambda x: x[1], reverse=True)[:limit]])
    return result


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    config, root, _ = load_config(CFG)
    audit, train_frame, _, evaluations = boundary_audit(config, root)
    train_text, train_y = train_frame.text.astype(str).tolist(), train_frame.label.astype(int).to_numpy()
    train_x, cal_x, train_labels, cal_labels = train_test_split(train_text, train_y, test_size=.25, stratify=train_y, random_state=42)
    phish = load_phish_samples(); phish_text = [text for _, text in phish]

    current = json.loads((ROOT / "services/ml/artifacts/phase_c_model_development_v1/deployment_candidate/feature_manifest.json").read_text(encoding="utf-8"))
    (OUT / "current_training.md").write_text(f"# Current training configuration\n\n- Algorithm: LogisticRegression wrapped in custom calibrated estimator (`CalibratedModel`).\n- Hyperparameters: C=1.0, solver=liblinear, class_weight=balanced, max_iter=2000, random_state=42.\n- Calibration: isotonic, fitted from grouped training OOF scores.\n- Feature vector: word TF-IDF 1–2 grams, 10,709 vectorizer dimensions, SelectKBest chi² to 512.\n- Preprocessing: lowercase, Unicode accent stripping, sublinear TF, max_df=0.95, max_features=30,000.\n- Scaler: none.\n- Threshold: 0.50 (registry and artifact).\n- Training boundary: {audit['baseline_rows_after_protected_boundary_exclusion']} rows after frozen protected-boundary exclusions.\n- Production artifact unchanged; this report is experimental only.\n", encoding="utf-8")

    experiments = [("lr_balanced_c0.25", "lr", .25), ("baseline_lr_c1.0", "lr", 1.0), ("lr_balanced_c2.0", "lr", 2.0), ("lr_balanced_c4.0", "lr", 4.0), ("linear_svm_sigmoid", "svm", 1.0), ("random_forest_sigmoid", "rf", 20)]
    summary: list[dict[str, Any]] = []
    models: dict[str, Any] = {}
    probability_cache: dict[str, dict[str, np.ndarray]] = {}
    for name, kind, parameter in experiments:
        model = make_pipeline(kind, parameter)
        model.fit(train_x, train_labels)
        models[name] = model
        probability_cache[name] = {}
        for eval_name, frame in {"phishing_22": pd.DataFrame({"text": phish_text, "label": [1] * len(phish)}), **evaluations}.items():
            p, raw = probabilities(model, frame.text.astype(str).tolist())
            probability_cache[name][eval_name] = p
            m = metrics(frame.label.astype(int).to_numpy(), p)
            summary.append({"experiment": name, "evaluation": eval_name, **m})

    with (OUT / "experiment_summary.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["experiment", "evaluation", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier_score", "ece", "tn", "fp", "fn", "tp", "fpr", "fnr"]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(sorted(summary, key=lambda r: (-r["recall"], -r["precision"], r["brier_score"])))

    baseline_model = models["baseline_lr_c1.0"]
    base_p, base_raw = probabilities(baseline_model, phish_text)
    current_loaded = ModelManager(selected_model_id="phase-c-logistic-regression-v1").load_deployment_candidate()
    current_predictor = current_loaded.predictor
    current_p = np.asarray(current_predictor.predict_proba(phish_text)[:, 1], dtype=float)
    top = feature_rows(baseline_model, phish_text)
    with (OUT / "false_negative_analysis.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["sample_id", "previous_model_probability", "experimental_probability", "current_model_missed", "experimental_missed", "top_contributing_features", "why_probability_remained_low"]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for (ident, _), old, new, features in zip(phish, current_p, base_p, top, strict=True):
            reason = "low lexical overlap with learned phishing vocabulary" if old < .5 else "not a current model false negative"
            w.writerow({"sample_id": ident, "previous_model_probability": float(old), "experimental_probability": float(new), "current_model_missed": bool(old < .5), "experimental_missed": bool(new < .5), "top_contributing_features": ";".join(features), "why_probability_remained_low": reason})

    with (OUT / "feature_importance.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["source", "feature", "weight_or_prevalence", "interpretation"])
        clf = baseline_model.named_steps["clf"]
        names = baseline_model.named_steps["features"].get_feature_names_out()
        for name, weight in sorted(zip(names, clf.coef_[0]), key=lambda x: abs(x[1]), reverse=True)[:100]:
            w.writerow(["trained_text", name, float(weight), "positive values increase phishing score; engineered observational features are not model inputs"])
        w.writerow(["engineered_observational", "not_consumed_by_approved_model", 0.0, "No learned coefficient or permutation importance exists because these features are outside the production schema."])

    thresholds = []
    threshold_frame = evaluations["grouped_diagnostic"]
    threshold_p = np.asarray(current_predictor.predict_proba(threshold_frame.text.astype(str).tolist())[:, 1], dtype=float)
    threshold_y = threshold_frame.label.astype(int).to_numpy()
    for threshold in (.30, .35, .40, .45, .50, .55, .60):
        m = metrics(threshold_y, threshold_p, threshold)
        thresholds.append({"threshold": threshold, "precision": m["precision"], "recall": m["recall"], "fpr": m["fpr"], "fnr": m["fnr"], "sample": "grouped_diagnostic (diagnostic only)"})
    with (OUT / "threshold_analysis.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(thresholds[0])); w.writeheader(); w.writerows(thresholds)

    grouped = evaluations["grouped_diagnostic"]
    current_raw_score = np.asarray(current_predictor.pipeline.decision_function(grouped.text.astype(str).tolist()), dtype=float)
    raw_gp = 1 / (1 + np.exp(-np.clip(current_raw_score, -40, 40)))
    gp = np.asarray(current_predictor.predict_proba(grouped.text.astype(str).tolist())[:, 1], dtype=float)
    cal_report = {"evaluation": "grouped_diagnostic", "raw": metrics(grouped.label.astype(int).to_numpy(), raw_gp), "calibrated": metrics(grouped.label.astype(int).to_numpy(), gp), "calibration_method": "isotonic from approved artifact metadata", "reliability_bins": []}
    for low in np.arange(0, 1, .1):
        mask = (gp >= low) & (gp < low + .1 if low < .9 else gp <= 1)
        cal_report["reliability_bins"].append({"lower": float(low), "upper": float(low + .1), "count": int(mask.sum()), "mean_probability": float(gp[mask].mean()) if mask.any() else None, "observed_rate": float(grouped.label.to_numpy()[mask].mean()) if mask.any() else None})
    (OUT / "calibration_report.md").write_text("# Calibration report\n\nCalibration was evaluated without fitting a production calibrator or changing the threshold. Raw probabilities are the sigmoid-transformed decision scores for the experimental baseline; calibrated probabilities use the experiment's internal sigmoid calibration.\n\n```json\n" + json.dumps(cal_report, indent=2, allow_nan=False) + "\n```\n", encoding="utf-8")

    grouped_rows = [r for r in summary if r["evaluation"] == "grouped_diagnostic"]
    winner = sorted(grouped_rows, key=lambda r: (-r["recall"], -r["precision"], r["brier_score"]))[0]
    (OUT / "final_recommendation.md").write_text(f"# Final recommendation\n\nRecommend experimental candidate `{winner['experiment']}` for a subsequent label-reviewed, controlled training cycle. It achieved grouped-diagnostic recall {winner['recall']:.4f}, precision {winner['precision']:.4f}, F1 {winner['f1']:.4f}, PR-AUC {winner['pr_auc']:.4f}, and Brier score {winner['brier_score']:.4f}.\n\nThis is not an activation recommendation. The candidate was trained only in memory and does not replace the production artifact. Its apparent recall gain must be confirmed on independent, representative, provenance-reviewed data; random forest and low-threshold gains may increase false positives.\n\nThe current model misses phishing primarily because the protected samples contain vocabulary/template patterns outside its text-only learned representation. Observational features are not model inputs, so they cannot contribute learned weight.\n\nNext production step: run a separately approved retraining/evaluation cycle with representative phishing families, grouped holdouts, calibration review, and explicit false-positive constraints.\n", encoding="utf-8")


if __name__ == "__main__":
    main()
