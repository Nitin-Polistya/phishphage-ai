"""Source-membership artifact inventory and safe text normalisation.

This module is deliberately independent of the phishing classifier.  It only
fits the existing source-membership diagnostic probe and writes privacy-safe
aggregate reports; input datasets are never modified.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline

ARTIFACT_DEFINITIONS = [
    ("headers", "KEEP", r"(?im)^(received|return-path|x-[^:]+|authentication-results):"),
    ("return_path_patterns", "EXPERIMENTAL", r"(?im)^return-path:"),
    ("x_headers", "EXPERIMENTAL", r"(?im)^x-[^:]+:"),
    ("date_formatting", "SAFE_TO_NORMALIZE", r"(?im)^date:\s*[^\r\n]+"),
    ("sender_domains", "EXPERIMENTAL", r"(?i)\bfrom:\s*[^\n@]+@([^\s>]+)"),
    ("recipient_patterns", "SAFE_TO_REMOVE", r"(?i)(?:to|delivered-to|x-forwarded-to):[^\n]+"),
    ("subject_prefixes", "EXPERIMENTAL", r"(?im)^subject:\s*(?:re|fwd?|aw):"),
    ("message_ids", "SAFE_TO_NORMALIZE", r"(?im)^message-id:\s*<[^>]+>"),
    ("reply_to", "EXPERIMENTAL", r"(?im)^reply-to:"),
    ("authentication", "KEEP", r"(?im)^authentication-results:"),
    ("url_domains", "KEEP", r"https?://[^/\s>]+"),
    ("url_paths", "KEEP", r"https?://[^\s>]+/[^\s>]+"),
    ("html_comments", "SAFE_TO_NORMALIZE", r"(?s)<!--.*?-->") ,
    ("css", "EXPERIMENTAL", r"(?is)<style[^>]*>.*?</style>"),
    ("boilerplate_css", "EXPERIMENTAL", r"(?is)<style[^>]*>.*?</style>"),
    ("boilerplate_html", "EXPERIMENTAL", r"(?is)<meta[^>]+generator|<font[^>]*>"),
    ("hidden_text", "KEEP", r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden)"),
    ("footer_text", "EXPERIMENTAL", r"(?im)(?:unsubscribe|manage preferences)"),
    ("lexical_tokens", "KEEP", r"(?i)\b(?:password|credential|login|invoice|urgent)\b"),
    ("whitespace_patterns", "SAFE_TO_NORMALIZE", r"\s{3,}"),
    ("character_encoding", "SAFE_TO_NORMALIZE", r"(?i)=\?[^?]+\?[bq]\?[^?]+\?="),
    ("mime_structure", "SAFE_TO_NORMALIZE", r"(?im)^--[-_a-z0-9]+"),
    ("boundary_strings", "SAFE_TO_NORMALIZE", r"(?i)boundary\s*=\s*[^;\s]+"),
    ("tracking_ids", "SAFE_TO_REMOVE", r"(?i)[?&](?:utm_[a-z_]+|fbclid|gclid|mc_cid|mc_eid)="),
    ("attachment_metadata", "KEEP", r"(?im)^(?:content-disposition|content-type):.*attachment"),
    ("collection_metadata", "SAFE_TO_REMOVE", r"(?i)\b(?:honeypot|phishing[ _-]?pot|trap mailbox)\b"),
    ("sender_infrastructure", "EXPERIMENTAL", r"(?im)^(?:received|return-path):"),
]

_SAFE_PATTERNS = {
    "message_ids": re.compile(r"(?im)^message-id:\s*<[^>]+>") ,
    "html_comments": re.compile(r"(?s)<!--.*?-->") ,
    "collection_metadata": re.compile(r"(?i)\b(?:honeypot|phishing[ _-]?pot|trap mailbox)\b"),
    "tracking_ids": re.compile(r"(?i)([?&](?:utm_[a-z_]+|fbclid|gclid|mc_cid|mc_eid))=[^&#\s>]+"),
    "mime_boundary": re.compile(r"(?im)(boundary\s*=\s*[\"']?)[^\s;\"']+"),
}


def _probe_auc(texts: list[str], labels: np.ndarray, seed: int = 42) -> tuple[float, dict[str, float]]:
    pipe = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=10000)),
                     ("clf", LogisticRegression(class_weight="balanced", random_state=seed, solver="liblinear"))])
    folds = StratifiedKFold(5, shuffle=True, random_state=seed)
    probabilities = cross_val_predict(pipe, texts, labels, cv=folds, method="predict_proba")[:, 1]
    auc = float(roc_auc_score(labels, probabilities))
    pipe.fit(texts, labels)
    names = pipe.named_steps["tfidf"].get_feature_names_out(); coef = pipe.named_steps["clf"].coef_[0]
    ranked = sorted(zip(names, coef), key=lambda x: abs(float(x[1])), reverse=True)
    # Feature identifiers only: do not put raw source tokens in reports.
    importance = {hashlib.sha256(t.encode()).hexdigest()[:16]: float(v) for t, v in ranked[:50]}
    return auc, importance


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Apply only SAFE_TO_REMOVE/SAFE_TO_NORMALIZE transforms."""
    value = str(text)
    applied: list[str] = []
    for name, pattern, replacement in (("message_ids", _SAFE_PATTERNS["message_ids"], "Message-ID: <NORMALIZED>"),
                                       ("html_comments", _SAFE_PATTERNS["html_comments"], " "),
                                       ("tracking_ids", _SAFE_PATTERNS["tracking_ids"], r"\1=<TRACKING_ID>"),
                                       ("mime_boundary", _SAFE_PATTERNS["mime_boundary"], r"\1<NORMALIZED_BOUNDARY>"),
                                       ("collection_metadata", _SAFE_PATTERNS["collection_metadata"], " ")):
        value, count = pattern.subn(replacement, value)
        if count:
            applied.extend([name] * count)
    value = re.sub(r"[ \t]{3,}", " ", value)
    return value.strip(), applied


def source_artifact_normalization(text: str) -> str:
    """Public convenience transform used by audits (never changes source files)."""
    return normalize_text(text)[0]


def run_artifact_reduction(config_path: str | Path, output_dir: str | Path | None = None,
                           max_iterations: int = 5, seed: int = 42) -> dict[str, Any]:
    config_file = Path(config_path).resolve(); config = json.loads(config_file.read_text(encoding="utf-8"))
    root = next(parent for parent in config_file.parents if (parent / "services" / "ml").exists())
    baseline = pd.read_csv(root / config["paths"]["baseline"]); weak_rows = [json.loads(x) for x in (root / config["paths"]["weak_manifest"]).read_text(encoding="utf-8").splitlines() if x.strip()]
    baseline_phish = baseline.loc[baseline.label.astype(int).eq(1), "text"].fillna("").astype(str).tolist()
    weak = [str(row.get("text", "")) for row in weak_rows]
    labels = np.r_[np.zeros(len(baseline_phish), dtype=int), np.ones(len(weak), dtype=int)]
    original = baseline_phish + weak
    out = Path(output_dir) if output_dir else root / "services/ml/reports/artifact_reduction_v1"; out.mkdir(parents=True, exist_ok=True)
    inventory = [{"artifact": n, "classification": c, "pattern": p, "justification": "Collection metadata is removable; phishing semantics are preserved." if c.startswith("SAFE") else "Requires preservation or further review."} for n, c, p in ARTIFACT_DEFINITIONS]
    old_auc, old_importance = _probe_auc(original, labels, seed)
    history = [{"iteration": 0, "auc": old_auc, "transforms": []}]; current = original; transforms = []
    for iteration in range(1, max_iterations + 1):
        normalized = [normalize_text(t)[0] for t in current]
        applied = sorted({a for t in current for a in normalize_text(t)[1]})
        if normalized == current or not applied: break
        auc, importance = _probe_auc(normalized, labels, seed)
        history.append({"iteration": iteration, "auc": auc, "transforms": applied})
        transforms.extend(applied); current = normalized
        if auc < 0.75: break
    final_auc, final_importance = _probe_auc(current, labels, seed)
    summary = {"initial_auc": old_auc, "final_auc": final_auc, "difference": final_auc - old_auc,
               "iterations": len(history)-1, "features_removed": sorted(set(transforms)),
               "features_normalized": sorted(set(transforms)), "features_preserved": [n for n, c, _ in ARTIFACT_DEFINITIONS if c == "KEEP"],
               "classifier_retrained": False, "datasets_modified": False}
    (out / "artifact_inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (out / "artifact_importance.json").write_text(json.dumps({"initial_auc": old_auc, "final_auc": final_auc,
        "initial_top_features_hashed": old_importance, "final_top_features_hashed": final_importance}, indent=2), encoding="utf-8")
    (out / "artifact_transform_log.json").write_text(json.dumps({"transforms": transforms,
        "iterations": history[1:], "raw_content_included": False}, indent=2), encoding="utf-8")
    (out / "source_probe_iteration_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    (out / "remaining_source_features.json").write_text(json.dumps({"top_features_hashed": final_importance}, indent=2), encoding="utf-8")
    (out / "artifact_reduction_summary.md").write_text("# Artifact reduction summary\n\n" + json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
