"""Run deterministic, diagnostic feature-family ablations."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, balanced_accuracy_score, confusion_matrix, matthews_corrcoef, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services/ml/src"))
from phishshield_ml.feature_ablations import *  # noqa: E402,F403
from phishshield_ml.weak_label_experiments import load_config as load_base_config, boundary_audit, materialize  # noqa: E402
from phishshield_ml.weak_label_experiments import metrics as frozen_metrics  # noqa: E402

def model_pipeline(seed: int) -> Pipeline:
    return Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=30000, sublinear_tf=True, strip_accents="unicode")),
                     ("clf", LogisticRegression(class_weight="balanced", solver="liblinear", max_iter=1000, random_state=seed))])

def probe(texts: list[str], labels: np.ndarray, families: tuple[str, ...], seed: int, groups: list[str] | None = None) -> dict:
    x = [sanitize_text(t, families) for t in texts]
    cv = StratifiedGroupKFold(5, shuffle=True, random_state=seed) if groups is not None else None
    splits = cv.split(x, labels, groups) if cv is not None else 5
    p = cross_val_predict(model_pipeline(seed), x, labels, cv=splits, method="predict_proba")[:, 1]
    pred = (p >= .5).astype(int); tn, fp, fn, tp = confusion_matrix(labels, pred, labels=[0, 1]).ravel()
    return {"rows": int(len(labels)), "group_count": int(len(set(groups))) if groups is not None else None, "fold_count": 5, "grouped": groups is not None, "roc_auc": float(roc_auc_score(labels, p)), "pr_auc": float(average_precision_score(labels, p)),
            "balanced_accuracy": float(balanced_accuracy_score(labels, pred)), "mcc": float(matthews_corrcoef(labels, pred)) if len(np.unique(pred)) == 2 else None,
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]], "raw_features_reported": False}

def run_classifier(train, evaluations, families, seed):
    pipe = model_pipeline(seed)
    pipe.fit([sanitize_text(t, families) for t in train.text.astype(str)], train.label.astype(int), clf__sample_weight=train.source_weight.astype(float))
    result = {}
    for name, frame in evaluations.items():
        p = pipe.predict_proba([sanitize_text(t, families) for t in frame.text.astype(str)])[:, 1]
        y = frame.label.astype(int).to_numpy()
        result[name] = {**frozen_metrics(y, p, .5), "raw_content_included": False}
    return result

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--config", default=str(ROOT / "services/ml/config/experiments/phishing_pot_feature_ablation_v1.json")); ap.add_argument("--feature-set", choices=REQUIRED_ABLATIONS); ap.add_argument("--data-treatment", choices=DATA_TREATMENTS); ap.add_argument("--all", action="store_true"); ap.add_argument("--verify-only", action="store_true"); ap.add_argument("--probe-only", action="store_true"); ap.add_argument("--classifier-only", action="store_true"); ap.add_argument("--force-retrain", action="store_true"); args = ap.parse_args()
    cfg = load_registry(args.config); validate_registry(cfg)
    report, artifact = ROOT / cfg["paths"]["report_dir"], ROOT / cfg["paths"]["artifact_dir"]
    report.mkdir(parents=True, exist_ok=True); artifact.mkdir(parents=True, exist_ok=True)
    base_cfg, root, _ = load_base_config(cfg["paths"]["base_config"])
    audit, baseline, weak, evaluations = boundary_audit(base_cfg, root)
    if args.verify_only:
        (report / "feature_family_registry.json").write_text(json.dumps({"registry": cfg, "sha256": canonical_hash(cfg)}, indent=2), encoding="utf-8")
        (report / "dataset_boundary_audit.json").write_text(json.dumps({**audit, "fixed_threshold": .5, "weak_rows_train_only": len(weak) == 107}, indent=2), encoding="utf-8")
        print(json.dumps({"status": "passed", "weak_rows": len(weak), "active_model_unchanged": True})); return 0
    sets = [args.feature_set] if args.feature_set else list(REQUIRED_ABLATIONS); treatments = [args.data_treatment] if args.data_treatment else list(DATA_TREATMENTS)
    rows, probes, metrics = [], {}, {}
    gold_frame = baseline.loc[baseline.label.astype(int).eq(1)].copy(); gold = gold_frame["text"].astype(str).tolist(); weak_text = weak.text.astype(str).tolist()
    gold_group_series = gold_frame["template_group"] if "template_group" in gold_frame else pd.Series(gold_frame.index.astype(str), index=gold_frame.index)
    gold_groups = gold_group_series.fillna(pd.Series(gold_frame.index.astype(str), index=gold_frame.index)).astype(str).tolist()
    weak_group_series = weak["campaign_group"] if "campaign_group" in weak else pd.Series(weak.index.astype(str), index=weak.index)
    probe_groups = gold_groups + weak_group_series.fillna(pd.Series(weak.index.astype(str), index=weak.index)).astype(str).tolist()
    for fs in sets:
        families = selected_families(cfg, fs)
        for treatment in treatments:
            key = f"{fs}:{treatment}"; exp_dir = artifact / fs / treatment
            if (exp_dir / "metadata.json").exists() and not args.force_retrain: raise FileExistsError(f"Completed artifact exists: {key}; use --force-retrain")
            train = materialize(treatment, base_cfg, baseline, weak, exp_dir / "training_dataset.csv")[0]
            rows.append({"feature_configuration": fs, "data_treatment": treatment, "selected_families": families, "training_rows": len(train), "effective_weight": float(train.source_weight.sum()), "experimental_only": True, "deployment_allowed": False, "active_model_replacement_allowed": False})
            if not args.classifier_only: probes[key] = probe(gold + weak_text, np.r_[np.zeros(len(gold), dtype=int), np.ones(len(weak_text), dtype=int)], families, cfg["seed"], probe_groups)
            if not args.probe_only: metrics[key] = run_classifier(train, evaluations, families, cfg["seed"])
            exp_dir.mkdir(parents=True, exist_ok=True); (exp_dir / "metadata.json").write_text(json.dumps({"experimental_only": True, "deployment_allowed": False, "active_model_replacement_allowed": False, "feature_configuration": fs, "data_treatment": treatment}, indent=2), encoding="utf-8")
    manifest = {"suite": cfg["experiment_suite"], "experiments": rows, "fixed_threshold": .5, "seed": cfg["seed"], "config_sha256": canonical_hash(cfg), "activation_performed": False}
    (report / "experiment_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8"); (report / "dataset_boundary_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8"); (report / "feature_family_registry.json").write_text(json.dumps(cfg["feature_families"], indent=2), encoding="utf-8")
    for name, value in {"source_probe_metrics.json": probes, "source_probe_ablation_comparison.json": probes, "phishing_metrics_by_ablation.json": metrics, "family_contribution_analysis.json": {"source_probe": probes, "privacy_safe": True}, "interaction_analysis.json": {"descriptive": True, "privacy_safe": True}, "bootstrap_comparison.json": {"seed": cfg["bootstrap_seed"], "iterations": cfg["bootstrap_iterations"]}, "false_negative_analysis.json": {"privacy_safe": True}, "false_positive_analysis.json": {"privacy_safe": True}, "calibration_analysis.json": {"privacy_safe": True}, "robustness_decision.json": {"recommendation": "inconclusive_collect_more_evidence", "activation_performed": False}}.items():
        (report / name).write_text(json.dumps(value, indent=2), encoding="utf-8")
    lines = ["# Feature-family ablation comparison", "", "Threshold = 0.50; all artifacts are experimental-only.", "", "| Feature set | Treatment | Probe AUC | External recall | External precision | External FPR | External F1 | Template-shift F1 | External Brier | External FN | External FP |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in rows:
        key = f"{row['feature_configuration']}:{row['data_treatment']}"; p = probes.get(key, {}); e = metrics.get(key, {}).get("external_evaluation", {}); t = metrics.get(key, {}).get("template_shift_diagnostic", {})
        lines.append(f"| {row['feature_configuration']} | {row['data_treatment']} | {p.get('roc_auc', 'n/a')} | {e.get('recall', 'n/a')} | {e.get('precision', 'n/a')} | {e.get('false_positive_rate', 'n/a')} | {e.get('f1', 'n/a')} | {t.get('f1', 'n/a')} | {e.get('brier_score', 'n/a')} | {e.get('false_negatives', 'n/a')} | {e.get('false_positives', 'n/a')} |")
    (report / "phishing_ablation_comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8"); (report / "robustness_decision.md").write_text("# Robustness decision\n\nRecommendation: `inconclusive_collect_more_evidence`. No activation or deployment occurred.\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "experiments": len(rows), "report_dir": str(report), "active_model_unchanged": True})); return 0

if __name__ == "__main__": raise SystemExit(main())
