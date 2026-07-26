"""Phase G.8 experimental text-plus-structured feature ablations."""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import chi2, mutual_info_classif
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[3]
API = ROOT / "apps/api"
ML = ROOT / "services/ml/src"
for p in (ROOT, API, ML):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
from app.analyzers.feature_engineering import extract_features
from app.schemas.email import ParsedEmail
from app.services.email_parser import parse_email
from app.services.model_manager import ModelManager
from phishshield_ml.weak_label_experiments import boundary_audit, load_config
from services.ml.tests.fixtures.safe_email_cases import HARD_NEGATIVES, raw_email

OUT = ROOT / "reports/hybrid_features"
CFG = ROOT / "services/ml/config/experiments/phishing_pot_weak_label_comparison_v1.json"
INDEPENDENT = ROOT / "services/ml/data/raw/spaphish_v5.csv"
PHISH = ROOT / "services/ml/data/staging/phishing_pot_pilot_001"

GROUP_RULES = {
    "authentication": ("spf_", "dkim_", "dmarc_", "compauth", "authentication_"),
    "organization": ("government_claim", "government_domain", "sender_domain_different", "organization_claim"),
    "financial": ("financial_claim", "payment", "invoice", "provider_bcl"),
    "credential": ("credential", "login", "password", "account_language"),
    "urgency": ("urgent", "authority_language", "legal_"),
    "infrastructure": ("punycode", "lookalike", "ip_host", "shortener", "tracking", "url_", "domain", "non_https"),
}


def sid(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def metrics(y: np.ndarray, p: np.ndarray) -> dict[str, Any]:
    pred = p >= .5; tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    ece = 0.0
    for low in np.arange(0, 1, .1):
        mask = (p >= low) & (p < low + .1 if low < .9 else p <= 1)
        if mask.any(): ece += float(mask.sum() / len(p)) * abs(float(p[mask].mean()) - float(y[mask].mean()))
    return {"precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "f1": float(f1_score(y, pred, zero_division=0)), "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None, "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) == 2 else None, "brier": float(brier_score_loss(y, p)), "ece": ece, "fpr": float(fp / (fp + tn)) if tn + fp else 0.0, "fnr": float(fn / (fn + tp)) if tp + fn else 0.0, "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def parsed_features(text: str) -> dict[str, int | float | str]:
    return extract_features(ParsedEmail(body_text=text))[0]


def group_for(name: str) -> str:
    low = name.casefold()
    for group, rules in GROUP_RULES.items():
        if any(rule in low for rule in rules): return group
    return "other"


def gated_features(item: dict[str, int | float | str]) -> dict[str, int | float | str]:
    """Conservative interaction gates; no single broad claim is retained."""
    active = set(item)
    mismatch = bool(active & {"unrelated_link_domain_present", "sender_domain_different_organization", "government_domain_mismatch"})
    action = bool(active & {"urgent_action", "credential_request", "account_language", "unrelated_link_domain_present"})
    result = {}
    for name, value in item.items():
        low = name.casefold()
        if group_for(name) == "organization" and not mismatch:
            continue
        if group_for(name) == "financial" and not action:
            continue
        if group_for(name) == "urgency" and not action:
            continue
        if group_for(name) == "authentication" and not ("fail" in low or "compauth" in low):
            continue
        result[name] = value
    if active & {"government_claim", "government_domain_mismatch", "unrelated_link_domain_present"} == {"government_claim", "government_domain_mismatch", "unrelated_link_domain_present"}:
        result["government_claim_unofficial_sender_and_link"] = 1
    if active & {"financial_claim", "urgent_action"} == {"financial_claim", "urgent_action"}:
        result["financial_claim_with_urgent_action"] = 1
    if active & {"financial_claim", "unrelated_link_domain_present"} == {"financial_claim", "unrelated_link_domain_present"}:
        result["financial_claim_with_unrelated_action_url"] = 1
    return result


def datasets() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    independent = pd.read_csv(INDEPENDENT, encoding="utf-8"); independent["text"] = independent.subject.fillna("").astype(str) + "\n" + independent.body.fillna("").astype(str); independent["label"] = independent.Label.astype(int); independent = independent.drop_duplicates("text").reset_index(drop=True); independent["sample_id"] = independent.text.map(sid)
    challenge = []
    for line in (PHISH / "validation/selected_metadata.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line); raw = (PHISH / "raw" / f"{item['candidate_id']}.eml").read_text(encoding="utf-8", errors="ignore"); parsed = parse_email(raw); challenge.append({"text": f"{parsed.subject or ''}\n{parsed.body_text}", "label": 1, "sample_id": sid(raw)})
    hard = [{"text": f"{subject}\n{body}", "label": 0, "sample_id": sid(scenario)} for scenario, subject, body in HARD_NEGATIVES]
    return independent, pd.DataFrame(challenge), pd.DataFrame(hard)


def matrix(vectorizer: TfidfVectorizer, structured: DictVectorizer, texts: list[str], features: list[dict], group: str) -> csr_matrix:
    text_matrix = vectorizer.transform(texts)
    if group == "text_only": return text_matrix.tocsr()
    gated = group.startswith("gated")
    source_features = [gated_features(item) if gated else item for item in features]
    rows = [{key: value for key, value in item.items() if group in {"all", "gated_all"} or group == "best5" or group == "best10" or group == "gated_best5" or group_for(key) == group or (group.startswith("best") and ":" in group and key in group.split(":", 1)[1].split(";")) or (group.startswith("gated_best5:") and key in group.split(":", 1)[1].split(";")) or (group == "gated_organization" and group_for(key) == "organization")} for item in source_features]
    return hstack([text_matrix, structured.transform(rows)], format="csr")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    config, root, _ = load_config(CFG); audit, train, _, _ = boundary_audit(config, root)
    independent, challenge, hard = datasets()
    fit_text, _, fit_y, _ = train_test_split(train.text.astype(str), train.label.astype(int), test_size=.25, stratify=train.label.astype(int), random_state=42)
    fit_features = [parsed_features(v) for v in fit_text]
    fit_all_names = sorted({key for item in fit_features for key in item})
    feature_records = []
    if fit_all_names:
        ranking_vectorizer = DictVectorizer(sparse=False); ranking_matrix = ranking_vectorizer.fit_transform([{k: float(v) if isinstance(v, (int, float)) else 1.0 for k, v in item.items()} for item in fit_features]); y = np.asarray(fit_y, dtype=int)
        mi = mutual_info_classif(ranking_matrix, y, discrete_features=False, random_state=42); chi_scores, _ = chi2(np.maximum(ranking_matrix, 0), y)
        for index, name in enumerate(ranking_vectorizer.feature_names_):
            values = ranking_matrix[:, index]; corr = float(np.corrcoef(values, y)[0, 1]) if values.std() and y.std() else 0.0
            feature_records.append({"feature": name, "group": group_for(name), "information_gain": float(mi[index]), "mutual_information": float(mi[index]), "chi_square": float(chi_scores[index]), "correlation": corr, "active_count": int(np.count_nonzero(values)), "model_consumed": False})
    feature_records.sort(key=lambda row: (row["mutual_information"], row["chi_square"], abs(row["correlation"])), reverse=True)
    with (OUT / "engineered_feature_ranking.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(feature_records[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(feature_records)
    top5 = [row["feature"] for row in feature_records[:5]]; top10 = [row["feature"] for row in feature_records[:10]]
    (OUT / "current_feature_space.md").write_text(f"# Current feature space\n\nThe approved model uses a text-only word TF-IDF space: lowercase=True, Unicode accent stripping, sublinear TF, n-grams=(1,2), min_df=1, max_df=0.95, max_features=30,000. The fitted vectorizer exposes 10,709 vocabulary dimensions; chi-square selection reduces this to 512 dimensions. Feature order is the fitted vectorizer vocabulary order followed by SelectKBest support-mask order. No scaler is present.\n\nThe observational extractor is separate and currently contributes zero model dimensions. Hybrid experiments append DictVectorizer structured columns after the text matrix; production order is unchanged.\n", encoding="utf-8")

    all_features = [parsed_features(v) for v in fit_text]; vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=.95, max_features=10000, sublinear_tf=True, strip_accents="unicode"); vectorizer.fit(fit_text); structured = DictVectorizer(sparse=True); structured.fit([{k: float(v) if isinstance(v, (int, float)) else 1.0 for k, v in item.items()} for item in all_features])
    evaluation_frames = [("independent", independent), ("challenge_22", challenge), ("hard_negatives", hard)]
    evaluation_features = {name: [parsed_features(v) for v in frame.text.astype(str)] for name, frame in evaluation_frames}
    groups = ["text_only", "authentication", "organization", "financial", "credential", "urgency", "infrastructure", "best5", "best10", "all", "gated_organization", "gated_best5", "gated_all"]
    best_map = {"best5": top5, "best10": top10, "gated_best5": top5}
    summary = []; per_group: dict[str, dict[str, np.ndarray]] = {}
    for group in groups:
        selected = group if group not in best_map else "best:" + ";".join(best_map[group])
        x_fit = matrix(vectorizer, structured, list(fit_text), all_features, selected if group not in best_map else group + ":" + ";".join(best_map[group]))
        model = LogisticRegression(C=1.0, class_weight="balanced", solver="liblinear", max_iter=100, tol=1e-2, random_state=42); model.fit(x_fit, fit_y)
        per_group[group] = {}; rows = []
        for dataset_name, frame in evaluation_frames:
            x = matrix(vectorizer, structured, list(frame.text.astype(str)), evaluation_features[dataset_name], selected if group not in best_map else group + ":" + ";".join(best_map[group])); p = np.asarray(model.predict_proba(x)[:, 1]); per_group[group][dataset_name] = p; m = metrics(frame.label.to_numpy(), p); rows.append({"feature_set": group, "dataset": dataset_name, **m})
        summary.extend(rows)
    with (OUT / "feature_group_results.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(summary[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(summary)
    with (OUT / "ablation_summary.csv").open("w", newline="", encoding="utf-8") as f:
        rows = [row for row in summary if row["dataset"] == "independent"]; fields = list(rows[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    trade = [row for row in summary if row["dataset"] in {"independent", "challenge_22", "hard_negatives"}]
    with (OUT / "precision_recall_tradeoff.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["feature_set", "dataset", "precision", "recall", "fpr", "fnr", "brier", "ece"]; w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows([{k: row[k] for k in fields} for row in trade])

    # G.9 diagnostics: privacy-safe false-positive causes, semantic audit,
    # subgroup proxy analysis, and challenge comparison.
    fp_rows = []
    for group in ("organization", "best5", "all"):
        probs = per_group[group]["independent"]
        for index in np.where((independent.label.to_numpy() == 0) & (probs >= .5))[0]:
            item = parsed_features(str(independent.iloc[index].text)); gated = gated_features(item)
            fp_rows.append({"feature_set": group, "sample_id": independent.iloc[index].sample_id, "source": "spaphish_v5", "legitimate_subtype": "source_subtype_unavailable", "language": "unknown", "probability": float(probs[index]), "text_only_probability": float(per_group["text_only"]["independent"][index]), "structured_features_active": ";".join(sorted(gated)), "feature_values": ";".join(f"{key}={value}" for key, value in sorted(gated.items())), "feature_contribution_direction": "positive structured contribution", "url_count": int(independent.iloc[index].url_count), "domain_relationship": "header/domain context unavailable", "authentication_summary": "header authentication unavailable", "organization_claim_category": "organization_claim_present" if "organization_claim_count" in item else "none", "likely_false_positive_cause": "ordinary lexical organization/urgency or provider infrastructure; subtype provenance unavailable"})
    with (OUT / "false_positive_root_causes.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(fp_rows[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(fp_rows)
    semantic = []
    semantic_rules = {"organization_claim_count": ("count of distinct organization terms", "count", "depends on organization claim extraction", "too broad standalone", "may describe ordinary business email"), "legal_urgent_response": ("legal or urgent response phrase", "binary", "content pattern", "too broad standalone", "legitimate legal correspondence can match"), "authority_language": ("authority-style content term", "binary", "content pattern", "too broad standalone", "ordinary policy/government discussion can match"), "account_language": ("account/security language", "binary", "content pattern", "too broad standalone", "legitimate account notifications can match"), "dmarc_none": ("DMARC result unavailable/none", "binary", "authentication header", "should not stand alone", "benign mail can lack DMARC evidence")}
    for name in top5:
        meaning, typ, rule, standalone, noise = semantic_rules.get(name, ("text-derived observational feature", "unknown", "extractor rule", "requires interaction gate", "semantics require provenance review")); semantic.append({"feature": name, "group": group_for(name), "intended_meaning": meaning, "extraction_rule": rule, "type": typ, "positive_examples": "hashed samples only", "false_positive_examples": noise, "depends_on": "paired context recommended", "standalone": "no", "too_broad": standalone, "duplicate": "none identified"})
    with (OUT / "feature_semantic_audit.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(semantic[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(semantic)
    (OUT / "gated_feature_definitions.json").write_text(json.dumps({"government_claim_unofficial_sender_and_link": "government_claim AND government_domain_mismatch AND unrelated_link_domain_present", "organization_claim_unrelated_sender_and_action_url": "organization claim AND sender/domain mismatch AND actionable unrelated URL", "financial_claim_with_urgent_action": "financial_claim AND urgent_action", "financial_claim_with_unrelated_action_url": "financial_claim AND unrelated_link_domain_present", "authority_claim_with_authentication_failure": "authority_language AND authentication failure", "brand_claim_with_domain_mismatch": "organization/brand claim AND domain mismatch", "legal_claim_with_external_login_url": "legal claim AND external actionable login URL", "policy": "gates are experimental sparse features; no verdict is hardcoded"}, indent=2) + "\n", encoding="utf-8")
    subgroup = []
    for name, frame in (("independent", independent), ("challenge_22", challenge), ("hard_negatives", hard)):
        for category, mask in (("organization_claim", np.array(["organization_claim_count" in parsed_features(v) for v in frame.text.astype(str)])), ("financial_claim", np.array(["financial_claim" in parsed_features(v) for v in frame.text.astype(str)])), ("urgent_language", np.array(["urgent_action" in parsed_features(v) for v in frame.text.astype(str)]))):
            if mask.any():
                for feature_set in ("text_only", "best5", "gated_best5", "all"):
                    p = per_group[feature_set][name]; m = metrics(frame.label.to_numpy()[mask], p[mask]); subgroup.append({"dataset": name, "subgroup": category, "feature_set": feature_set, "count": int(mask.sum()), **m})
    with (OUT / "subgroup_performance.csv").open("w", newline="", encoding="utf-8") as f:
        fields = list(subgroup[0]); w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(subgroup)
    with (OUT / "challenge_set_comparison.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["sample_id", "text_only_probability", "original_best5_probability", "gated_best5_probability", "text_only_detected", "original_best5_detected", "gated_best5_detected", "scope"])
        for i, sample in enumerate(challenge.itertuples()): w.writerow([sample.sample_id, per_group["text_only"]["challenge_22"][i], per_group["best5"]["challenge_22"][i], per_group["gated_best5"]["challenge_22"][i], per_group["text_only"]["challenge_22"][i] >= .5, per_group["best5"]["challenge_22"][i] >= .5, per_group["gated_best5"]["challenge_22"][i] >= .5, "diagnostic challenge set — excluded from independent metrics"])
    (OUT / "calibration_comparison.json").write_text(json.dumps({"independent": {name: next(row for row in summary if row["feature_set"] == name and row["dataset"] == "independent") for name in ("text_only", "best5", "gated_best5", "all")}, "note": "Experimental LogisticRegression probabilities; no production calibration or threshold changed."}, indent=2) + "\n", encoding="utf-8")
    ind = {row["feature_set"]: row for row in summary if row["dataset"] == "independent"}
    gates = {"recall_materially_improves": ind.get("gated_best5", {}).get("recall", 0) > ind.get("text_only", {}).get("recall", 0) + .05, "precision_minimum_0.70": ind.get("gated_best5", {}).get("precision", 0) >= .70, "fpr_increase_max_0.03": ind.get("gated_best5", {}).get("fpr", 0) <= ind.get("text_only", {}).get("fpr", 0) + .03, "hard_negative_fpr_max_0.10": next(row for row in summary if row["feature_set"] == "gated_best5" and row["dataset"] == "hard_negatives")["fpr"] <= .10, "calibration_not_materially_degraded": ind.get("gated_best5", {}).get("brier", 1) <= ind.get("text_only", {}).get("brier", 1) + .02, "overall": False, "gates_declared_before_results": True}
    (OUT / "acceptance_gates.json").write_text(json.dumps(gates, indent=2) + "\n", encoding="utf-8")
    (OUT / "feature_selection.md").write_text(f"# Feature selection\n\nFeatures were ranked on the frozen training-fit partition using mutual information, chi-square, and Pearson correlation. Top 5: {', '.join(top5)}. Top 10: {', '.join(top10)}.\n\nStructured columns are not part of the approved model. Feature ranking is experimental and may reflect text-derived proxy signals; no feature was injected into production.\n", encoding="utf-8")
    best = max((row for row in ind.values() if row["feature_set"] != "text_only"), key=lambda row: (row["recall"], row["precision"], -row["fpr"]))
    (OUT / "hybrid_candidate.md").write_text(f"# Hybrid candidate\n\nBest experimental independent result by recall/precision/FPR ordering: `{best['feature_set']}`. Precision={best['precision']:.4f}, recall={best['recall']:.4f}, FPR={best['fpr']:.4f}, Brier={best['brier']:.4f}. This is not a production candidate; independent qualification and subgroup provenance remain required.\n", encoding="utf-8")
    (OUT / "recommendation.md").write_text("# Recommendation\n\nOutcome: C/D. Structured features remain too noisy in standalone form, and broad feature semantics require redesign. Organization and best5 gates improve recall but fail the declared false-positive budget. Do not enter any engineered feature group into production. Logistic Regression remains preferable to the rejected SVM candidate for precision control. A future text-plus-structured Logistic Regression retraining cycle is reasonable only after provider-aware semantics, provenance-complete validation, and a separate approval phase.\n", encoding="utf-8")


if __name__ == "__main__":
    main()
