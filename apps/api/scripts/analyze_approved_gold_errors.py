"""Privacy-safe Phase IV.A false-negative analysis for the approved gold set."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
API_ROOT = ROOT / "apps" / "api"
ML_SRC = ROOT / "services" / "ml" / "src"
for path in (API_ROOT, ML_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.analyzers.feature_engineering import extract_features  # noqa: E402
from app.core.settings import get_settings  # noqa: E402
from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest, EmailAddress, ParsedEmail  # noqa: E402
from app.services.analysis_pipeline import AnalysisPipeline  # noqa: E402
from app.services.model_manager import ModelManager  # noqa: E402
from app.services.safety_fusion import evaluate_high_confidence_rule_evidence  # noqa: E402
from phishshield_ml.gold_dataset_error_analysis import (  # noqa: E402
    AnalysisObservation,
    calibration_report,
    feature_prevalence_rows,
    group_rows,
    output_file_hashes,
    privacy_safe_error_artifact_text,
    shift_summary,
    probability_band_rows,
    select_false_negatives,
    select_true_positives,
    threshold_rows,
)
from phishshield_ml.gold_dataset_evaluation import (  # noqa: E402
    EVALUATION_SCRIPT_VERSION,
    adapt_approved_records,
    load_approved_content,
    load_export_records,
    privacy_safe_artifact_text,
)


ANALYSIS_SCRIPT_VERSION = "gold-dataset-error-analysis-v1.0.0"
DEFAULT_DATASET = ROOT / "services/ml/evaluation/private/gold_dataset_reports/gold_dataset_v1.jsonl"
DEFAULT_REVIEW_DB = ROOT / "services/ml/evaluation/private/review_workspace.sqlite3"
DEFAULT_EVALUATION = ROOT / "services/ml/evaluation/private/gold_dataset_evaluation"
DEFAULT_OUTPUT = ROOT / "services/ml/evaluation/private/gold_dataset_error_analysis"
PRIVATE_ROOT = (ROOT / "services/ml/evaluation/private").resolve()
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp|javascript|data|file|blob|chrome):[^\s<>]+")
PATH_RE = re.compile(r"(?i)(?:[A-Za-z]:[\\/]|/Users/|/home/|/tmp/|/var/|file://)[^\s]+")
HEADER_RE = re.compile(r"(?im)^(?:from|to|cc|bcc|subject|received|message-id|authentication-results|return-path):")
HTML_RE = re.compile(r"(?is)<\s*/?\s*[a-z][^>]*>")
SECRET_RE = re.compile(r"(?i)\b(?:api[_ -]?key|admin[_ -]?token|access[_ -]?token|bearer)\s*[:=]\s*[^\s]+")
OFFICIAL_SUFFIXES = (".gov", ".gov.in", ".gov.uk", ".jus.br", ".gov.br", ".mil", ".edu")
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".link", ".live", ".today", ".online", ".site", ".one", ".work", ".icu", ".shop", ".win", ".loan", ".zip", ".mov"}
FREE_MAIL_DOMAINS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "aol.com"}


def _logical(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")


def _private(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError:
        raise ValueError("Analysis inputs and outputs must remain under private evaluation storage.") from None
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def _enum(value: Any) -> str:
    return str(getattr(value, "value", value))


def _safe_domain_category(domain: str) -> str:
    value = domain.casefold().strip().rstrip(".")
    if not value:
        return "absent_from_retained_metadata"
    if value in FREE_MAIL_DOMAINS:
        return "freemail"
    if any(value == suffix[1:] or value.endswith(suffix) for suffix in OFFICIAL_SUFFIXES):
        return "official_style_suffix"
    if any(value.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return "suspicious_tld"
    return "organizational_domain"


def _auth_category(values: Iterable[str]) -> str:
    text = " ".join(values).casefold()
    if not text.strip():
        return "absent_from_retained_metadata"
    if re.search(r"\b(?:spf|dkim|dmarc)\s*[=:]\s*pass\b", text):
        return "explicit_pass"
    if re.search(r"\b(?:spf|dkim|dmarc)\s*[=:]\s*fail\b", text):
        return "explicit_fail"
    if re.search(r"\b(?:softfail|neutral|none)\b", text):
        return "softfail_neutral_none"
    if re.search(r"\b(?:detected|referenced|present)\b", text):
        return "referenced_or_detected"
    return "malformed_or_unknown"


def _url_category(domains: Iterable[str], flags: Iterable[str]) -> str:
    domain_values = [value for value in domains if value.strip()]
    flag_text = " ".join(flags).casefold()
    if any(token in flag_text for token in ("mismatch", "lookalike", "ip_host", "shortener", "suspicious_tld", "non_https")):
        return "suspicious_or_mismatched_domain_evidence"
    if not domain_values and not flag_text.strip():
        return "no_retained_url_evidence"
    if domain_values and not flag_text.strip():
        return "domain_only"
    return "structural_url_evidence"


def _attachment_category(metadata: str) -> str:
    return "no_retained_attachment_metadata" if not metadata.strip() else "attachment_metadata_present"


def _vector_diagnostics(model: Any, text: str) -> dict[str, Any]:
    pipeline = getattr(model, "pipeline", None)
    steps = getattr(pipeline, "named_steps", {})
    vectorizer = steps.get("features") if isinstance(steps, dict) else None
    selector = steps.get("feature_selection") if isinstance(steps, dict) else None
    if vectorizer is None or not hasattr(vectorizer, "transform"):
        return {"text_length": len(text), "token_count": len(text.split()), "vocabulary_coverage": None, "oov_proportion": None, "nonzero_features": None, "nonzero_selected_features": None}
    matrix = vectorizer.transform([text])
    selected = selector.transform(matrix) if selector is not None else matrix
    analyzer = vectorizer.build_analyzer() if hasattr(vectorizer, "build_analyzer") else None
    tokens = list(analyzer(text)) if analyzer else text.split()
    vocabulary = getattr(vectorizer, "vocabulary_", {})
    known = sum(token in vocabulary for token in tokens)
    coverage = known / len(tokens) if tokens else 0.0
    return {
        "text_length": len(text),
        "token_count": len(tokens),
        "vocabulary_coverage": coverage,
        "oov_proportion": 1.0 - coverage if tokens else 0.0,
        "nonzero_features": int(matrix.nnz),
        "nonzero_selected_features": int(selected.nnz),
    }


def _safe_sender(domain: str) -> EmailAddress | None:
    if not domain:
        return None
    # This synthetic local part exists only in memory to exercise the existing
    # domain-aware feature extractor; it is never written to an artifact.
    return EmailAddress(address=f"analysis@{domain}")


def _build_observations(dataset_path: Path, review_db_path: Path) -> tuple[list[AnalysisObservation], dict[str, Any]]:
    exports = load_export_records(dataset_path)
    approved = load_approved_content(review_db_path)
    adapted = adapt_approved_records(exports, approved)
    if len(exports) != 75 or len(adapted) != 75:
        raise RuntimeError("The approved gold input must contain exactly 75 validated records.")
    settings = get_settings()
    manager = ModelManager(
        registry_path=settings.ml_registry_path,
        selected_model_id=settings.ml_model_id,
        artifact_override=settings.ml_artifact_path,
    )
    loaded = manager.load_deployment_candidate()
    pipeline = AnalysisPipeline(manager=manager)
    probabilities = [float(row[1]) for row in loaded.predictor.predict_proba([item.text for item in adapted])]
    adapted_by_id = {item.sample_id: item for item in adapted}
    exports_by_id = {str(row.values["source_sample_id_digest"]): row for row in exports}
    observations: list[AnalysisObservation] = []
    for item in sorted(adapted, key=lambda value: (value.sample_id, value.sample_hash)):
        export = exports_by_id[item.sample_id]
        content = approved[str(export.values["review_id"])]
        body = content.body_excerpt or content.subject
        request = AnalysisPreviewRequest(
            input_mode=AnalysisInputMode.quick_paste,
            subject=content.subject or None,
            body=body,
        )
        try:
            result = pipeline.run_request(request)
        except Exception as error:
            raise RuntimeError("Deterministic rule/fusion analysis failed for an approved record.") from error
        parsed = result.parser
        # Re-run the audited extractor explicitly so feature prevalence is tied
        # to the current feature_engineering.py contract, not report wording.
        engineered_features, _, _ = extract_features(parsed)
        signals = tuple(_value(signal, "code", "") for signal in (_value(result.rule_analysis, "signals", []) or []))
        high_signals = tuple(
            _value(signal, "code", "")
            for signal in (_value(result.rule_analysis, "signals", []) or [])
            if _enum(_value(signal, "severity", "")) == "high"
        )
        vector = _vector_diagnostics(loaded.predictor, item.text)
        evidence_summary = evaluate_high_confidence_rule_evidence(_value(result.rule_analysis, "signals", []) or [], parsed)
        observations.append(AnalysisObservation(
            sample_id=item.sample_id,
            sample_hash=item.sample_hash,
            source_dataset=item.source_dataset,
            campaign_id=str(export.values["campaign_identifier"]),
            language=str(export.values["language"]),
            label=item.label_name,
            probability=probabilities[sorted(adapted, key=lambda value: (value.sample_id, value.sample_hash)).index(item)],
            features=dict(engineered_features),
            text_length=vector["text_length"],
            token_count=vector["token_count"],
            vocabulary_coverage=vector["vocabulary_coverage"],
            oov_proportion=vector["oov_proportion"],
            nonzero_features=vector["nonzero_features"],
            nonzero_selected_features=vector["nonzero_selected_features"],
            strong_rule_signal_count=len(high_signals),
            rule_signal_count=len(signals),
            rule_signal_codes=tuple(sorted(signals)),
            authentication_bucket=_auth_category(content.authentication_summary),
            url_bucket=_url_category(content.url_domains, content.url_structural_flags),
            sender_domain_category=_safe_domain_category(content.sender_domain),
            attachment_category=_attachment_category(content.attachment_metadata),
            rule_classification=_enum(_value(result.rule_analysis, "classification", "")),
            decision_classification=_enum(_value(result.decision, "classification", "")),
            rule_score=_value(result, "rule_raw_score"),
            decision_score=_value(_value(result, "decision", {}), "risk_score"),
            fusion_performed=bool(_value(result.decision, "fusion_performed", False)),
            safety_floor_applied=bool(_value(result.decision, "safety_floor_applied", False)),
            missing_evidence_count=len(_value(_value(result, "analysis_completeness", {}), "missing_evidence", []) or []),
        ))
    metadata = {
        "model_id": loaded.record.model_id,
        "model_version": loaded.record.version,
        "model_artifact_sha256": loaded.record.sha256,
        "threshold": loaded.record.threshold,
        "calibration": loaded.record.calibration,
        "registry_activated": loaded.record.activated,
        "deployment_candidate": loaded.record.deployment_candidate,
        "baseline_evaluation": _logical(DEFAULT_EVALUATION / "evaluation_summary.json"),
    }
    return observations, metadata


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    text = json.dumps(_json_safe(payload), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if not _privacy_safe(text):
        raise RuntimeError("Refusing to write a privacy-unsafe JSON artifact.")
    path.write_text(text, encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    fields = fields or sorted({key for row in rows for key in row})
    output_rows: list[dict[str, Any]] = []
    for row in rows:
        output_rows.append({
            field: json.dumps(row.get(field), sort_keys=True, separators=(",", ":")) if isinstance(row.get(field), (dict, list)) else row.get(field, "")
            for field in fields
        })
    import io

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(output_rows)
    text = buffer.getvalue()
    if not _privacy_safe(text):
        raise RuntimeError("Refusing to write a privacy-unsafe CSV artifact.")
    path.write_text(text, encoding="utf-8")


def _write_markdown(path: Path, text: str) -> None:
    if not _privacy_safe(text):
        raise RuntimeError("Refusing to write a privacy-unsafe Markdown artifact.")
    path.write_text(text, encoding="utf-8")


def _privacy_safe(text: str) -> bool:
    return privacy_safe_error_artifact_text(text)


def _cohort_summary(observations: list[AnalysisObservation]) -> dict[str, Any]:
    return {
        "count": len(observations),
        "probability": {
            "mean": sum(item.probability for item in observations) / len(observations) if observations else None,
            "median": sorted(item.probability for item in observations)[len(observations) // 2] if observations else None,
            "min": min((item.probability for item in observations), default=None),
            "max": max((item.probability for item in observations), default=None),
        },
        "representation": {
            "text_length_mean": sum(item.text_length for item in observations) / len(observations) if observations else None,
            "token_count_mean": sum(item.token_count for item in observations) / len(observations) if observations else None,
            "vocabulary_coverage_mean": sum(item.vocabulary_coverage for item in observations if item.vocabulary_coverage is not None) / len([item for item in observations if item.vocabulary_coverage is not None]) if any(item.vocabulary_coverage is not None for item in observations) else None,
            "oov_proportion_mean": sum(item.oov_proportion for item in observations if item.oov_proportion is not None) / len([item for item in observations if item.oov_proportion is not None]) if any(item.oov_proportion is not None for item in observations) else None,
            "nonzero_features_mean": sum(item.nonzero_features for item in observations if item.nonzero_features is not None) / len([item for item in observations if item.nonzero_features is not None]) if any(item.nonzero_features is not None for item in observations) else None,
            "nonzero_selected_features_mean": sum(item.nonzero_selected_features for item in observations if item.nonzero_selected_features is not None) / len([item for item in observations if item.nonzero_selected_features is not None]) if any(item.nonzero_selected_features is not None for item in observations) else None,
        },
        "rule_evidence": {
            "samples_with_any_rule_signal": sum(item.rule_signal_count > 0 for item in observations),
            "samples_with_high_rule_signal": sum(item.strong_rule_signal_count > 0 for item in observations),
            "mean_rule_signal_count": sum(item.rule_signal_count for item in observations) / len(observations) if observations else None,
            "mean_missing_evidence_count": sum(item.missing_evidence_count for item in observations) / len(observations) if observations else None,
        },
    }


def _comparison_rows(observations: list[AnalysisObservation], threshold: float) -> list[dict[str, Any]]:
    cohorts = {
        "false_negative": select_false_negatives(observations, threshold),
        "true_positive": select_true_positives(observations, threshold),
        "safe": [item for item in observations if item.label == "safe"],
    }
    rows = []
    for cohort, members in cohorts.items():
        summary = _cohort_summary(members)
        rows.append({
            "cohort": cohort,
            "count": summary["count"],
            **{f"probability_{key}": value for key, value in summary["probability"].items()},
            **{f"representation_{key}": value for key, value in summary["representation"].items()},
            "rule_signal_any_count": summary["rule_evidence"]["samples_with_any_rule_signal"],
            "rule_high_signal_count": summary["rule_evidence"]["samples_with_high_rule_signal"],
            "mean_rule_signal_count": summary["rule_evidence"]["mean_rule_signal_count"],
            "mean_missing_evidence_count": summary["rule_evidence"]["mean_missing_evidence_count"],
            "fusion_performed_count": sum(item.fusion_performed for item in members),
            "safety_floor_applied_count": sum(item.safety_floor_applied for item in members),
            "rule_classification_distribution": dict(sorted(Counter(item.rule_classification for item in members).items())),
            "decision_classification_distribution": dict(sorted(Counter(item.decision_classification for item in members).items())),
            "source_distribution": dict(sorted(Counter(item.source_dataset for item in members).items())),
            "campaign_count": len({item.campaign_id for item in members}),
        })
    return rows


def _feature_highlights(rows: list[dict[str, Any]]) -> dict[str, Any]:
    common_fn = sorted(rows, key=lambda row: (-row["fn_prevalence"], row["feature"]))[:15]
    fn_vs_tp = sorted(rows, key=lambda row: (-row["fn_minus_tp"], row["feature"]))[:15]
    absent_from_fn = [row for row in rows if row["fn_prevalence"] == 0 and (row["tp_prevalence"] > 0 or row["safe_prevalence"] > 0)]
    absent_from_fn = sorted(absent_from_fn, key=lambda row: (-max(row["tp_prevalence"], row["safe_prevalence"]), row["feature"]))[:15]
    common_across_cohorts = [row for row in rows if row["fn_prevalence"] == row["tp_prevalence"] == row["safe_prevalence"] and row["fn_prevalence"] > 0]
    reversed_prevalence = [row for row in rows if row["fn_minus_tp"] < 0]
    reversed_prevalence = sorted(reversed_prevalence, key=lambda row: (row["fn_minus_tp"], row["feature"]))[:15]
    return {
        "most_common_in_false_negatives": common_fn,
        "largest_fn_minus_tp": fn_vs_tp,
        "absent_from_false_negatives": absent_from_fn,
        "common_across_fn_tp_safe_not_discriminative": common_across_cohorts,
        "reversed_fn_vs_tp_prevalence": reversed_prevalence,
    }


def _threshold_table_markdown(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["| Hypothetical threshold | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR | Balanced accuracy |", "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in rows:
        lines.append("| {threshold:.2f} | {tp} | {fp} | {tn} | {fn} | {precision:.3f} | {recall:.3f} | {f1:.3f} | {false_positive_rate:.3f} | {false_negative_rate:.3f} | {balanced_accuracy:.3f} |".format(**row))
    return lines


def _report_markdown(summary: dict[str, Any], thresholds: list[dict[str, Any]], calibration: dict[str, Any], groups: list[dict[str, Any]], features: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    top_groups = groups[:8]
    top_features = features["most_common_in_false_negatives"][:8]
    fn_comparison = next(row for row in summary["representation_comparison"] if row["cohort"] == "false_negative")
    lines = [
        "# Approved-gold false-negative error analysis",
        "",
        "This is an analysis-only report. No model, threshold, calibration, registry, dataset, or production behavior was changed.",
        "",
        "## Cohort and baseline",
        "",
        f"- Approved input records: **{summary['input_record_count']}**",
        f"- False negatives: **{summary['false_negative_count']}** (required cohort: phishing label with probability below `{summary['threshold']:.2f}`)",
        f"- Class balance: safe **{summary['class_distribution']['safe']}**, phishing **{summary['class_distribution']['phishing']}**",
        f"- Baseline accuracy / precision / recall / F1: **{baseline['accuracy']:.4f} / {baseline['precision']:.4f} / {baseline['recall']:.4f} / {baseline['f1']:.4f}**",
        f"- Baseline false positives / false negatives: **{baseline['false_positive_count']} / {baseline['false_negative_count']}**",
        "- All identifiers in this report are privacy-safe digests; message text and evidence values are intentionally omitted.",
        "",
        "## Probability bands",
        "",
        "The false-negative bands use lower-inclusive, upper-exclusive boundaries. Correctly detected phishing is summarized separately for comparison.",
        "",
    ]
    for row in summary["false_negative_probability_bands"]:
        lines.append(f"- `{row['band']}`: **{row['count']}** ({row['percentage']:.1f}%), mean `{row['mean']}`, median `{row['median']}`")
    lines.extend(["", "## Most common false-negative groups", ""])
    for row in top_groups:
        lines.append(f"- `{row['group']}`: **{row['count']}** ({row['percentage_of_false_negatives']:.1f}%) — {row['definition']}")
    lines.extend(["", "## Feature prevalence", "", "Features are the existing deterministic engineered feature names. Prevalence is binary presence within each cohort; no feature evidence text is emitted.", ""])
    for row in top_features:
        lines.append(f"- `{row['feature']}`: FN `{row['fn_prevalence']:.3f}`, TP `{row['tp_prevalence']:.3f}`, safe `{row['safe_prevalence']:.3f}`")
    lines.append("")
    absent = features["absent_from_false_negatives"][:8]
    lines.append("Features absent from every FN but present elsewhere:")
    lines.append("")
    if absent:
        lines.extend(f"- `{row['feature']}`: TP `{row['tp_prevalence']:.3f}`, safe `{row['safe_prevalence']:.3f}`" for row in absent)
    else:
        lines.append("- None in the audited feature union.")
    common_features = features["common_across_fn_tp_safe_not_discriminative"][:8]
    lines.extend(["", "Features with the same positive prevalence across FN, TP, and safe cohorts:", ""])
    lines.extend(f"- `{row['feature']}`: `{row['fn_prevalence']:.3f}` in all cohorts" for row in common_features) if common_features else lines.append("- None.")
    reversed_features = features["reversed_fn_vs_tp_prevalence"][:8]
    lines.extend(["", "Features with lower FN prevalence than TP prevalence:", ""])
    lines.extend(f"- `{row['feature']}`: FN `{row['fn_prevalence']:.3f}`, TP `{row['tp_prevalence']:.3f}`" for row in reversed_features) if reversed_features else lines.append("- None.")
    lines.extend(["", "## Source, campaign, authentication, and URL findings", "", "- The phishing cohort is concentrated in one hashed source dataset; the safe cohort is concentrated in a different hashed source dataset.", "- The phishing records span seven hashed campaign identifiers, with the largest campaign families represented in the private JSON report only by digest and count.", "- Authentication metadata is absent from all retained approved records. No explicit pass, fail, softfail, neutral, or none result is available; passing authentication must not be inferred.", "- URL domains and structural URL flags are absent from all retained approved records. These samples therefore cannot be attributed to a domain mismatch, suspicious TLD, shortener, IP host, non-HTTPS link, or official-looking domain from retained metadata.", "- Attachment metadata is absent from all retained approved records.", "- The absence of retained metadata is a dataset-context limitation, not proof that the original messages had no authentication, URLs, or attachments.", "", "## Representation and rule/fusion findings", "", f"- False-negative representation statistics and TP/safe comparisons are in `true_positive_comparison.csv`.", f"- The calibrated model's fixed probabilities and current threshold are unchanged; expected calibration error is `{calibration['expected_calibration_error']:.4f}` using fixed reliability bins.", f"- On the FN cohort, `{fn_comparison['rule_signal_any_count']}` records had at least one rule signal, `{fn_comparison['rule_high_signal_count']}` had a high-severity rule signal, and `{fn_comparison['fusion_performed_count']}` used the existing fusion path. These are descriptive diagnostics only.", "- The `*_none` engineered features in the table represent parser defaults from missing retained authentication headers; they must not be interpreted as explicit authentication results.", "", "## Hypothetical threshold diagnostic", "", "These rows are hypothetical analysis only; no value was written to settings or the registry.", ""])
    lines.extend(_threshold_table_markdown(thresholds))
    lines.extend(["", "## Calibration diagnostic", "", "No recalibrator was fitted. Reliability bins, ECE, and near/far threshold FN distances are in `calibration_diagnostic.json`.", "", "## Recommendation matrix", "", "| Option | Evidence | Risk / limitation | Current 75-sample sufficiency |", "|---|---|---|---|"])
    matrix = [
        ("Threshold tuning only", "Lower hypothetical thresholds recover some FN records.", "False positives rise; threshold is a policy change requiring a separate validation set.", "Insufficient for deployment."),
        ("Recalibration", f"Fixed-bin ECE is {calibration['expected_calibration_error']:.4f}; probabilities can be compared with observed outcomes.", "No calibration fit is justified without a larger independent calibration set.", "Insufficient."),
        ("Engineered-feature fusion", "The existing rule/fusion diagnostics provide additional deterministic evidence on sanitized previews.", "Retained headers, URLs, and attachments are absent, so fusion coverage is incomplete.", "Insufficient for a change."),
        ("Controlled retraining", "High FN count and representation/source concentration indicate a possible coverage gap.", "One phishing source and 50 phishing records do not establish generalization or a safe training target.", "Not sufficient."),
        ("More gold-data review", "The cohort is source- and campaign-concentrated and context-limited.", "Requires additional human review effort.", "Recommended next step."),
        ("No change", "Preserves the verified production baseline.", "Leaves 24 phishing false negatives unexplained.", "Keep production unchanged while collecting evidence."),
    ]
    lines.extend(f"| {option} | {evidence} | {risk} | {sufficiency} |" for option, evidence, risk, sufficiency in matrix)
    lines.extend(["", "## Decision", "", "The recommended next action is more privacy-safe gold-data review and error analysis, especially additional phishing samples from independent sources and records retaining explicit authentication/URL/attachment metadata. Do not tune, recalibrate, fuse, retrain, or deploy based on this 75-record set alone.", ""])
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--review-db", type=Path, default=DEFAULT_REVIEW_DB)
    parser.add_argument("--evaluation-dir", type=Path, default=DEFAULT_EVALUATION)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dataset_path = _private(args.dataset)
    review_db_path = _private(args.review_db)
    evaluation_dir = _private(args.evaluation_dir)
    output_dir = _private(args.output_dir)
    if not dataset_path.is_file() or not review_db_path.is_file():
        raise FileNotFoundError("The approved gold export or private review store is missing.")
    if not evaluation_dir.is_dir():
        raise FileNotFoundError("The verified gold evaluation artifact directory is missing.")

    observations, model_metadata = _build_observations(dataset_path, review_db_path)
    threshold = float(model_metadata["threshold"])
    false_negatives = select_false_negatives(observations, threshold)
    true_positives = select_true_positives(observations, threshold)
    safe = [item for item in observations if item.label == "safe"]
    if len(false_negatives) != 24:
        raise RuntimeError(f"Expected exactly 24 approved phishing false negatives; found {len(false_negatives)}.")
    if len(true_positives) != 26 or len(safe) != 25:
        raise RuntimeError("The current verified cohort does not match the expected 26 TP / 25 safe records.")

    timestamp = datetime.now(timezone.utc).isoformat()
    dataset_hash = _sha256(dataset_path)
    baseline_path = evaluation_dir / "evaluation_summary.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected_identity = {
        "dataset_sha256": dataset_hash,
        "model_id": model_metadata["model_id"],
        "model_version": model_metadata["model_version"],
        "model_artifact_sha256": model_metadata["model_artifact_sha256"],
        "threshold": threshold,
    }
    for key, value in expected_identity.items():
        if baseline.get(key) != value:
            raise RuntimeError(f"Verified baseline identity mismatch for {key}.")

    bands = probability_band_rows(false_negatives, cohort_name="false_negative")
    feature_rows = feature_prevalence_rows(observations, threshold)
    groups = group_rows(observations, threshold)
    threshold_diagnostics = threshold_rows(observations)
    calibration = calibration_report(observations, threshold)
    shifts = shift_summary(observations, threshold)
    comparison = _comparison_rows(observations, threshold)
    feature_highlights = _feature_highlights(feature_rows)

    baseline_metrics = {key: baseline[key] for key in ("accuracy", "precision", "recall", "f1", "false_positive_count", "false_negative_count", "roc_auc", "pr_auc", "brier_score")}
    summary = {
        "analysis_script_version": ANALYSIS_SCRIPT_VERSION,
        "evaluation_script_version": EVALUATION_SCRIPT_VERSION,
        "analysis_timestamp": timestamp,
        "dataset_path": _logical(dataset_path),
        "dataset_sha256": dataset_hash,
        "evaluation_artifacts": _logical(evaluation_dir),
        "model": model_metadata,
        "threshold": threshold,
        "input_record_count": len(observations),
        "class_distribution": {"safe": len(safe), "phishing": len(false_negatives) + len(true_positives)},
        "false_negative_count": len(false_negatives),
        "false_negative_sample_ids": [item.sample_id for item in false_negatives],
        "true_positive_count": len(true_positives),
        "duplicate_hashes_rejected": True,
        "baseline": baseline_metrics,
        "false_negative_probability_bands": bands,
        "false_negative_source_distribution": dict(sorted(Counter(item.source_dataset for item in false_negatives).items())),
        "false_negative_campaign_distribution": dict(sorted(Counter(item.campaign_id for item in false_negatives).items())),
        "feature_highlights": feature_highlights,
        "groups": groups,
        "representation_comparison": comparison,
        "source_shift_summary": shifts,
        "calibration_summary": {
            "expected_calibration_error": calibration["expected_calibration_error"],
            "near_false_negative_count": calibration["false_negative_distance_to_threshold"]["near_within_0.10"]["count"],
            "far_false_negative_count": calibration["false_negative_distance_to_threshold"]["farther_than_0.10"]["count"],
        },
        "privacy": {
            "raw_message_content_emitted": False,
            "email_addresses_emitted": False,
            "raw_headers_emitted": False,
            "complete_urls_emitted": False,
            "query_strings_emitted": False,
            "attachment_contents_emitted": False,
            "absolute_paths_emitted": False,
            "api_keys_or_admin_tokens_emitted": False,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "false_negative_summary.json", summary)
    _write_csv(output_dir / "false_negative_probability_bands.csv", bands, ["cohort", "band", "lower_inclusive", "upper_exclusive", "count", "percentage", "mean", "median", "min", "max", "source_distribution", "campaign_distribution"])
    _write_csv(output_dir / "false_negative_feature_prevalence.csv", feature_rows, ["feature", "fn_count", "fn_prevalence", "tp_count", "tp_prevalence", "safe_count", "safe_prevalence", "fn_minus_tp", "fn_minus_safe"])
    _write_csv(output_dir / "false_negative_groups.csv", groups, ["group", "definition", "count", "percentage_of_false_negatives", "source_distribution", "campaign_distribution"])
    _write_csv(output_dir / "threshold_diagnostic.csv", threshold_diagnostics, ["hypothetical", "threshold", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "balanced_accuracy"])
    _write_json(output_dir / "calibration_diagnostic.json", calibration)
    _write_json(output_dir / "source_shift_summary.json", shifts)
    _write_csv(output_dir / "true_positive_comparison.csv", comparison)
    _write_markdown(output_dir / "error_analysis_report.md", _report_markdown(summary, threshold_diagnostics, calibration, groups, feature_highlights))

    artifact_names = [
        "false_negative_summary.json",
        "false_negative_probability_bands.csv",
        "false_negative_feature_prevalence.csv",
        "false_negative_groups.csv",
        "threshold_diagnostic.csv",
        "calibration_diagnostic.json",
        "source_shift_summary.json",
        "true_positive_comparison.csv",
        "error_analysis_report.md",
    ]
    manifest = {
        "status": "complete",
        "analysis_script_version": ANALYSIS_SCRIPT_VERSION,
        "evaluation_script_version": EVALUATION_SCRIPT_VERSION,
        "analysis_timestamp": timestamp,
        "dataset_path": _logical(dataset_path),
        "dataset_sha256": dataset_hash,
        "evaluation_artifacts": _logical(evaluation_dir),
        "input_record_count": len(observations),
        "false_negative_count": len(false_negatives),
        "model_id": model_metadata["model_id"],
        "model_version": model_metadata["model_version"],
        "model_artifact_sha256": model_metadata["model_artifact_sha256"],
        "threshold": threshold,
        "calibration": model_metadata["calibration"],
        "registry_activated": model_metadata["registry_activated"],
        "output_directory": _logical(output_dir),
        "output_file_sha256": {_logical(output_dir / name): digest for name, digest in output_file_hashes(str(output_dir), artifact_names).items()},
        "privacy": summary["privacy"],
        "manifest_hash_scope": "All analysis artifacts except this manifest; avoids self-referential hashing.",
    }
    _write_json(output_dir / "error_analysis_manifest.json", manifest)
    print(json.dumps({"status": "complete", "false_negative_count": len(false_negatives), "output_directory": _logical(output_dir), "analysis_timestamp": timestamp}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
