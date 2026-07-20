"""Safe, deterministic feature-family ablation utilities (diagnostic only)."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
    brier_score_loss, confusion_matrix, matthews_corrcoef, precision_score,
    recall_score, f1_score, roc_auc_score)

FAMILIES = ("lexical_text", "sender_infrastructure", "url_infrastructure", "authentication_headers", "mime_html_structure", "semantic_security_indicators", "metadata_misc")
DATA_TREATMENTS = ("baseline", "weak_035", "weak_050")
REQUIRED_ABLATIONS = ("baseline_full", "weak_035_full", "weak_050_full", "text_only", "structured_only", "without_sender_infrastructure", "without_url_infrastructure", "without_mime_html_structure", "without_authentication_headers", "without_lexical_text", "semantic_indicators_only", "lexical_plus_semantic", "infrastructure_only")
FEATURE_FAMILY_REGISTRY_VERSION = "phishing_pot_feature_ablation_v1"

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def load_registry(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def validate_registry(registry: dict) -> None:
    families = registry.get("feature_families", {})
    if tuple(families) != FAMILIES:
        raise ValueError("Registry must define every feature family exactly once")
    seen: set[str] = set()
    prohibited = set(registry.get("prohibited_raw_identifiers", []))
    for family, features in families.items():
        if not features: raise ValueError(f"Empty feature family: {family}")
        for feature in features:
            if feature in seen: raise ValueError(f"Feature assigned to multiple families: {feature}")
            if feature in prohibited or any(x in feature.lower() for x in ("raw_address", "full_url", "message_id", "filename")):
                raise ValueError(f"Prohibited raw identifier in registry: {feature}")
            seen.add(feature)
    ablations = registry.get("ablations", {})
    if set(REQUIRED_ABLATIONS) != set(ablations): raise ValueError("Required ablation definitions are incomplete")
    all_families = set(FAMILIES)
    for name, spec in ablations.items():
        inc, exc = set(spec.get("include", [])), set(spec.get("exclude", []))
        if inc & exc or not inc <= all_families or not exc <= all_families: raise ValueError(f"Invalid family selection: {name}")
        if name.endswith("_full") and inc != all_families: raise ValueError(f"Full ablation is incomplete: {name}")
    for treatment, value in registry.get("data_treatments", {}).items():
        if treatment not in DATA_TREATMENTS: raise ValueError(f"Unknown treatment: {treatment}")
    if registry.get("fixed_threshold", .5) != .5: raise ValueError("Fixed threshold must remain 0.50")

def selected_families(registry: dict, ablation: str) -> tuple[str, ...]:
    validate_registry(registry)
    spec = registry["ablations"][ablation]; all_families = set(FAMILIES)
    selected = set(spec.get("include", [])) or (all_families - set(spec.get("exclude", [])))
    return tuple(f for f in FAMILIES if f in selected)

def sanitize_text(text: str, families: tuple[str, ...]) -> str:
    """Deterministically mask disabled structured families; never alters source data."""
    value = str(text or "")
    if "lexical_text" not in families: value = re.sub(r"\b\w+\b", "TOKEN", value)
    if "url_infrastructure" not in families: value = re.sub(r"https?://\S+|www\.\S+", " URL ", value, flags=re.I)
    if "sender_infrastructure" not in families: value = re.sub(r"[\w.+-]+@[\w.-]+", " SENDER ", value)
    if "mime_html_structure" not in families: value = re.sub(r"<[^>]+>", " HTML ", value)
    if "authentication_headers" not in families: value = re.sub(r"(?im)^(authentication-results|received|return-path|arc-\w+):.*$", " HEADER ", value)
    if "semantic_security_indicators" not in families:
        value = re.sub(r"(?i)password|credential|login|invoice|payment|urgent|suspend|verify|otp|mfa", " SIGNAL ", value)
    return value

def classification_metrics(y_true: Any, probability: Any, threshold: float = .5) -> dict:
    y = np.asarray(y_true, dtype=int); p = np.asarray(probability, dtype=float); pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel(); both = len(np.unique(y)) == 2
    ratio = lambda a,b: float(a/b) if b else None
    return {"rows": int(len(y)), "true_positives": int(tp), "true_negatives": int(tn), "false_positives": int(fp), "false_negatives": int(fn), "confusion_matrix": [[int(tn),int(fp)],[int(fn),int(tp)]], "precision": ratio(tp,tp+fp), "recall": ratio(tp,tp+fn), "specificity": ratio(tn,tn+fp), "false_positive_rate": ratio(fp,tn+fp), "false_negative_rate": ratio(fn,fn+tp), "f1": float(f1_score(y,pred)) if tp+fp+fn else None, "balanced_accuracy": float(balanced_accuracy_score(y,pred)) if both else None, "mcc": float(matthews_corrcoef(y,pred)) if both and len(np.unique(pred))==2 else None, "roc_auc": float(roc_auc_score(y,p)) if both else None, "pr_auc": float(average_precision_score(y,p)) if both else None, "brier_score": float(brier_score_loss(y,p)), "mean_probability_by_class": {"legitimate": float(p[y==0].mean()) if (y==0).any() else None, "phishing": float(p[y==1].mean()) if (y==1).any() else None}, "undefined_metrics_are_null": True}

def paired_bootstrap(y: Any, left: Any, right: Any, iterations: int = 300, seed: int = 271828) -> dict:
    y = np.asarray(y); left = np.asarray(left); right = np.asarray(right); rng = np.random.default_rng(seed); out=[]
    for _ in range(iterations):
        idx = rng.integers(0,len(y),len(y)); a=classification_metrics(y[idx],left[idx]); b=classification_metrics(y[idx],right[idx]);
        if a["recall"] is not None and b["recall"] is not None: out.append(b["recall"]-a["recall"])
    return {"metric":"recall", "point_delta": classification_metrics(y,right)["recall"]-classification_metrics(y,left)["recall"], "ci95": [float(np.percentile(out,2.5)),float(np.percentile(out,97.5))] if out else None, "iterations": iterations, "seed": seed}

def grouped_source_probe_splits(groups: Any, n_splits: int = 5, seed: int = 42) -> list[tuple[np.ndarray, np.ndarray]]:
    """Deterministic group-disjoint folds for source probes (no group leakage)."""
    groups = np.asarray(groups); unique = np.asarray(sorted(set(groups.astype(str))))
    rng = np.random.default_rng(seed); rng.shuffle(unique)
    buckets = [set(unique[i::n_splits]) for i in range(n_splits)]
    return [(np.asarray([str(g) not in buckets[i] for g in groups]), np.asarray([str(g) in buckets[i] for g in groups])) for i in range(n_splits)]

def robustness_decision(baseline: dict, candidate: dict, policy: dict) -> dict:
    checks = {"external_recall": candidate.get("recall",0) >= baseline.get("recall",0)-policy.get("external_recall_max_decrease",.02), "external_fpr": candidate.get("false_positive_rate",0) <= baseline.get("false_positive_rate",0)+policy.get("external_fpr_max_increase",.02), "brier": candidate.get("brier_score",0) <= baseline.get("brier_score",0)+policy.get("brier_max_increase",.02)}
    return {"checks": checks, "robust": all(checks.values()), "activation_performed": False}
