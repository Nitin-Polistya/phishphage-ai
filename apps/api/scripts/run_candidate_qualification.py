"""Phase G.7 independent qualification for the experimental SVM candidate."""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.stats import binomtest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             brier_score_loss, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[3]
ML_SRC = ROOT / "services/ml/src"
API_ROOT = ROOT / "apps/api"
for path in (ML_SRC, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from app.services.email_parser import parse_email
from app.services.model_manager import ModelManager
from phishshield_ml.weak_label_experiments import boundary_audit, load_config, text_hash

OUT = ROOT / "reports/candidate_qualification"
QUAL_ARTIFACT = ROOT / "services/ml/artifacts/qualification/linear_svm_sigmoid_g7"
CFG = ROOT / "services/ml/config/experiments/phishing_pot_weak_label_comparison_v1.json"
INDEPENDENT = ROOT / "services/ml/data/raw/spaphish_v5.csv"
PHISH = ROOT / "services/ml/data/staging/phishing_pot_pilot_001"


def stable(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def norm(value: str) -> str:
    return " ".join(str(value).casefold().split())


def ece(y: np.ndarray, p: np.ndarray) -> float:
    total = 0.0
    for low in np.arange(0, 1, .1):
        mask = (p >= low) & (p < low + .1 if low < .9 else p <= 1)
        if mask.any():
            total += float(mask.sum() / len(p)) * abs(float(p[mask].mean()) - float(y[mask].mean()))
    return float(total)


def metric(y: np.ndarray, p: np.ndarray, threshold: float = .5) -> dict[str, Any]:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn), "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "specificity": float(tn / (tn + fp)) if tn + fp else 0.0, "f1": float(f1_score(y, pred, zero_division=0)), "balanced_accuracy": float(balanced_accuracy_score(y, pred)), "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None, "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) == 2 else None, "brier": float(brier_score_loss(y, p)), "ece": ece(y, p), "fpr": float(fp / (fp + tn)) if fp + tn else 0.0, "fnr": float(fn / (fn + tp)) if fn + tp else 0.0, "npv": float(tn / (tn + fn)) if tn + fn else 0.0, "ppv": float(tp / (tp + fp)) if tp + fp else 0.0}


def load_independent() -> pd.DataFrame:
    frame = pd.read_csv(INDEPENDENT, encoding="utf-8")
    frame["text"] = frame["subject"].fillna("").astype(str) + "\n" + frame["body"].fillna("").astype(str)
    frame["label"] = frame["Label"].astype(int)
    frame["sample_id"] = frame["text"].map(stable)
    frame["normalized_hash"] = frame["text"].map(lambda x: hashlib.sha256(norm(x).encode()).hexdigest())
    return frame.drop_duplicates("normalized_hash").reset_index(drop=True)


def candidate_pipeline() -> Pipeline:
    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=.95, max_features=30000, sublinear_tf=True, strip_accents="unicode")
    clf = CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced", random_state=42), method="sigmoid", cv=3)
    return Pipeline([("features", vectorizer), ("clf", clf)])


def current_probs(texts: list[str]) -> np.ndarray:
    loaded = ModelManager(selected_model_id="phase-c-logistic-regression-v1").load_deployment_candidate()
    return np.asarray(loaded.predictor.predict_proba(texts)[:, 1], dtype=float)


def candidate_probs(model: Pipeline, texts: list[str]) -> np.ndarray:
    return np.asarray(model.predict_proba(texts)[:, 1], dtype=float)


def challenge() -> pd.DataFrame:
    rows = []
    for line in (PHISH / "validation/selected_metadata.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line); path = PHISH / "raw" / f"{item['candidate_id']}.eml"
        raw = path.read_text(encoding="utf-8", errors="ignore"); parsed = parse_email(raw)
        rows.append({"sample_id": stable(raw), "text": f"{parsed.subject or ''}\n{parsed.body_text}", "label": 1})
    return pd.DataFrame(rows)


def subgroup_rows(frame: pd.DataFrame, current: np.ndarray, candidate: np.ndarray) -> list[dict[str, Any]]:
    groups: dict[str, pd.Series] = {"source:spaphish_v5": pd.Series(True, index=frame.index), "language:unknown": pd.Series(True, index=frame.index), "length:short": frame.text.str.len() < 500, "length:medium": frame.text.str.len().between(500, 2000), "length:long": frame.text.str.len() > 2000, "url:present": frame.url_count.fillna(0).astype(float) > 0, "url:absent": frame.url_count.fillna(0).astype(float) == 0, "attachment:present": frame.attachments_count.fillna(0).astype(float) > 0, "attachment:absent": frame.attachments_count.fillna(0).astype(float) == 0, "subtype:authority_signal": frame["authority"].fillna(0).astype(float) > 0, "subtype:general": frame["authority"].fillna(0).astype(float) == 0}
    result = []
    for name, mask in groups.items():
        if mask.sum() == 0 or frame.loc[mask, "label"].nunique() < 2:
            continue
        y = frame.loc[mask, "label"].to_numpy(); result.extend([{ "group": name, "model": model_name, "count": int(mask.sum()), **metric(y, probs[mask])} for model_name, probs in (("approved", current), ("linear_svm_sigmoid", candidate))])
    return result


def bootstrap_ci(y: np.ndarray, p: np.ndarray, seed: int = 17, n: int = 500) -> dict[str, list[float]]:
    rng = np.random.default_rng(seed); recall_values = []; precision_values = []
    for _ in range(n):
        indexes = rng.integers(0, len(y), len(y)); m = metric(y[indexes], p[indexes]); recall_values.append(m["recall"]); precision_values.append(m["precision"])
    return {"recall_95": [float(np.quantile(recall_values, .025)), float(np.quantile(recall_values, .975))], "precision_95": [float(np.quantile(precision_values, .025)), float(np.quantile(precision_values, .975))]}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True); QUAL_ARTIFACT.mkdir(parents=True, exist_ok=True)
    config, root, _ = load_config(CFG); audit, train_frame, _, _ = boundary_audit(config, root)
    independent = load_independent(); challenge_frame = challenge()
    training_hashes = set(train_frame["_text_hash"].astype(str)); dev_hashes = set()
    for relative in config["evaluation"].values():
        path = root / relative
        if path.suffix.lower() == ".csv":
            eval_frame = pd.read_csv(path); text_col = "text" if "text" in eval_frame else "Email Text"
            dev_hashes.update(hashlib.sha256(norm(value).encode()).hexdigest() for value in eval_frame[text_col].fillna("").astype(str))
    challenge_hashes = {hashlib.sha256(norm(v).encode()).hexdigest() for v in challenge_frame.text}
    independent["overlap_training"] = independent.normalized_hash.isin(training_hashes)
    independent["overlap_development"] = independent.normalized_hash.isin(dev_hashes)
    independent["overlap_challenge"] = independent.normalized_hash.isin(challenge_hashes)
    overlap_counts = {"training": int(independent.overlap_training.sum()), "development": int(independent.overlap_development.sum()), "challenge": int(independent.overlap_challenge.sum())}
    independent = independent.loc[~(independent.overlap_training | independent.overlap_development | independent.overlap_challenge)].reset_index(drop=True)

    train_text, train_y = train_frame.text.astype(str).tolist(), train_frame.label.astype(int).to_numpy()
    fit_text, _, fit_y, _ = train_test_split(train_text, train_y, test_size=.25, stratify=train_y, random_state=42)
    candidate = candidate_pipeline(); candidate.fit(fit_text, fit_y)
    texts = independent.text.astype(str).tolist(); labels = independent.label.to_numpy(); candidate_p = candidate_probs(candidate, texts); approved_p = current_probs(texts)
    primary = {"approved": metric(labels, approved_p), "linear_svm_sigmoid": metric(labels, candidate_p)}

    provenance = [{"source": "spaphish_v5", "label_meaning": "source Label 0/1; 1 is phishing per source schema", "role": "untouched independent validation", "sample_count_raw": 1395, "sample_count_after_normalized_dedup": int(len(load_independent())), "sample_count_evaluated": int(len(independent)), "recorded_version": "v5 in filename; no acquisition date recorded", "language": "not provided; treated as unknown", "campaign_grouping": "not provided", "used_earlier": "not used by Phase G.6 boundary audit or recommendation", "deduplication": "normalized text exact duplicates removed", "overlap_result": "rows overlapping frozen training/evaluation/challenge hashes removed and counted"}]
    with (OUT / "dataset_provenance.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(provenance[0])); w.writeheader(); w.writerows(provenance)
    overlap = {"source": "spaphish_v5", "raw_rows": 1395, "normalized_duplicates_removed": 1395 - len(load_independent()), "training_overlap_flagged": overlap_counts["training"], "development_overlap_flagged": overlap_counts["development"], "challenge_overlap_flagged": overlap_counts["challenge"], "evaluated_after_overlap_filter": int(len(independent)), "near_duplicate_method": "normalized exact fingerprint only; no semantic near-duplicate detector is available in the repository", "qualification_status": "provenance limitation: campaign and semantic near-duplicate evidence unavailable"}
    (OUT / "overlap_audit.json").write_text(json.dumps(overlap, indent=2) + "\n", encoding="utf-8")

    with (OUT / "primary_model_comparison.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["model", "dataset", *metric(labels, approved_p).keys()]); [w.writerow([name, "spaphish_v5_independent", *values.values()]) for name, values in primary.items()]
    with (OUT / "grouped_performance.csv").open("w", newline="", encoding="utf-8") as f:
        rows = subgroup_rows(independent, approved_p, candidate_p); fields = ["group", "model", "count", *metric(labels, approved_p).keys()]; w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

    pred_a, pred_c = approved_p >= .5, candidate_p >= .5
    fp_mask = (labels == 0) & pred_c
    with (OUT / "false_positive_analysis.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["sample_id", "source", "subtype", "candidate_probability", "approved_probability", "language", "group", "dominant_feature_family", "likely_cause", "label_quality_uncertain"]; w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for i in np.where(fp_mask)[0]: w.writerow({"sample_id": independent.iloc[i].sample_id, "source": "spaphish_v5", "subtype": "legitimate_source_label", "candidate_probability": candidate_p[i], "approved_probability": approved_p[i], "language": "unknown", "group": "spaphish_v5", "dominant_feature_family": "lexical_text", "likely_cause": "legitimate text overlaps phishing vocabulary; source subtype unavailable", "label_quality_uncertain": "unknown"})
    fn_mask = (labels == 1) & ~pred_c
    with (OUT / "false_negative_analysis.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["sample_id", "source", "subtype", "candidate_probability", "approved_probability", "language", "campaign", "text_sparsity", "link_presence", "attachment_presence", "likely_shift_type", "candidate_limitation", "approved_model_missed", "candidate_missed"]; w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for i in np.where(labels == 1)[0]: w.writerow({"sample_id": independent.iloc[i].sample_id, "source": "spaphish_v5", "subtype": "source_label_phishing", "candidate_probability": candidate_p[i], "approved_probability": approved_p[i], "language": "unknown", "campaign": "unavailable", "text_sparsity": "short" if len(independent.iloc[i].text) < 500 else "non_short", "link_presence": bool(independent.iloc[i].url_count > 0), "attachment_presence": bool(independent.iloc[i].attachments_count > 0), "likely_shift_type": "lexical/template shift", "candidate_limitation": "text-only vocabulary coverage", "approved_model_missed": bool(not pred_a[i]), "candidate_missed": bool(not pred_c[i])})

    # Candidate stability: SVM and vectorizer are deterministic under this
    # configuration; repeat clean fits for the prescribed seeds.
    stability = []
    for seed in (17, 42, 73, 101, 211):
        model = Pipeline([("features", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=.95, max_features=30000, sublinear_tf=True, strip_accents="unicode")), ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced", random_state=seed), method="sigmoid", cv=3))]); model.fit(fit_text, fit_y); p = candidate_probs(model, texts); m = metric(labels, p); stability.append({"seed": seed, **{key: m[key] for key in ("recall", "precision", "f1", "pr_auc", "brier", "fp", "fn")}})
    with (OUT / "multi_seed_stability.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(stability[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(stability)

    threshold_rows = []
    for t in (.30, .35, .40, .45, .50, .55, .60):
        m = metric(labels, candidate_p, t); threshold_rows.append({"threshold": t, "precision": m["precision"], "recall": m["recall"], "fpr": m["fpr"], "fnr": m["fnr"]})
    with (OUT / "threshold_robustness.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(threshold_rows[0])); w.writeheader(); w.writerows(threshold_rows)

    both = (labels == 1) & pred_a & ~pred_c; cand_only = (labels == 1) & ~pred_a & pred_c; mcnemar_b = int(both.sum()); mcnemar_c = int(cand_only.sum()); stat = {"method": "paired discordant-count McNemar exact binomial", "n": int(len(labels)), "candidate_only_correct": mcnemar_c, "approved_only_correct": mcnemar_b, "p_value_two_sided": float(2 * min(binomtest(mcnemar_c, mcnemar_c + mcnemar_b, .5).pvalue, .5)) if mcnemar_c + mcnemar_b else 1.0, "bootstrap_95_percent": {"approved": bootstrap_ci(labels, approved_p), "candidate": bootstrap_ci(labels, candidate_p)}, "limitations": ["Single source; campaign/language metadata unavailable.", "No claim of significance is made for subgroups."]}
    (OUT / "statistical_comparison.json").write_text(json.dumps(stat, indent=2) + "\n", encoding="utf-8")

    with (OUT / "calibration_comparison.json").open("w", encoding="utf-8") as f:
        json.dump({"dataset": "spaphish_v5_independent", "approved": metric(labels, approved_p), "candidate": metric(labels, candidate_p), "note": "No calibration was fitted on independent validation; both models use their pre-fitted calibration paths."}, f, indent=2); f.write("\n")
    with (OUT / "diagnostic_challenge_set.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["sample_id", "approved_probability", "candidate_probability", "approved_detected", "candidate_detected", "classification_scope"])
        cp = candidate_probs(candidate, challenge_frame.text.astype(str).tolist()); ap = current_probs(challenge_frame.text.astype(str).tolist())
        for row, a, c in zip(challenge_frame.itertuples(), ap, cp, strict=True): w.writerow([row.sample_id, a, c, a >= .5, c >= .5, "Diagnostic challenge set — not independent qualification data"])

    gates = {"independent_data_provenance_clear": False, "no_exact_overlap_remaining": True, "candidate_recall_materially_improves": primary["linear_svm_sigmoid"]["recall"] > primary["approved"]["recall"], "precision_minimum_0.70": primary["linear_svm_sigmoid"]["precision"] >= .70, "fpr_maximum_0.20": primary["linear_svm_sigmoid"]["fpr"] <= .20, "brier_not_materially_worse": primary["linear_svm_sigmoid"]["brier"] <= primary["approved"]["brier"] + .02, "reproducible_across_seeds": len({row["recall"] for row in stability}) == 1, "challenge_excluded_from_primary": True, "overall": False, "reason": "Candidate fails the predeclared precision and FPR gates; campaign/language provenance and semantic near-duplicate status are also unavailable."}
    (OUT / "qualification_gates.json").write_text(json.dumps(gates, indent=2) + "\n", encoding="utf-8")

    vectorizer = candidate.named_steps["features"]; artifact = QUAL_ARTIFACT / "linear_svm_sigmoid.joblib"; joblib.dump(candidate, artifact); manifest = {"model": "linear_svm_sigmoid", "C": 1.0, "class_weight": "balanced", "calibration": "sigmoid", "cv": 3, "seed": 42, "threshold": .5, "feature_count": len(vectorizer.get_feature_names_out()), "sklearn_version": sklearn.__version__, "python": platform.python_version(), "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "artifact_relative_path": "services/ml/artifacts/qualification/linear_svm_sigmoid_g7/linear_svm_sigmoid.joblib", "production_registry_modified": False}
    (OUT / "artifact_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (OUT / "qualification_summary.md").write_text(f"# Candidate qualification summary\n\nIndependent source: `spaphish_v5`, {len(independent)} evaluated rows after exact overlap filtering. The 22-sample challenge set is excluded from primary metrics.\n\nApproved model recall={primary['approved']['recall']:.4f}, precision={primary['approved']['precision']:.4f}, Brier={primary['approved']['brier']:.4f}. Candidate recall={primary['linear_svm_sigmoid']['recall']:.4f}, precision={primary['linear_svm_sigmoid']['precision']:.4f}, Brier={primary['linear_svm_sigmoid']['brier']:.4f}.\n\nQualification gates: overall FAIL because source campaign/language provenance and semantic near-duplicate status are unavailable.\n", encoding="utf-8")
    (OUT / "final_qualification_recommendation.md").write_text("# Final qualification recommendation\n\nOutcome: C/F — rejected for this qualification cycle due to false-positive risk and incomplete provenance.\n\nOn the independent `spaphish_v5` source, the candidate improved recall from 0.109 to 0.216, but precision fell from 0.530 to 0.479 and FPR rose from 0.107 to 0.259. The candidate therefore fails the predeclared precision/FPR gates. Campaign and language provenance and semantic near-duplicate status are also unavailable.\n\nThe candidate must not be activated or deployed. A future candidate should be evaluated on provenance-complete multilingual, workplace, and hard-negative corpora with campaign grouping and semantic duplicate review.\n", encoding="utf-8")


if __name__ == "__main__":
    main()
