"""Pure deterministic diagnostics for approved-gold false negatives.

This module accepts privacy-safe observations produced by the analysis runner.
It deliberately has no access to message text, headers, domains, or model
artifacts; only aggregate-safe fields and feature names are retained here.
"""

from __future__ import annotations

import math
import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import mean, median
from typing import Any, Mapping, Sequence


THRESHOLD_BANDS = (
    ("0.00-0.10", 0.00, 0.10),
    ("0.10-0.20", 0.10, 0.20),
    ("0.20-0.30", 0.20, 0.30),
    ("0.30-0.40", 0.30, 0.40),
    ("0.40-0.50", 0.40, 0.50),
)
HYPOTHETICAL_THRESHOLDS = (0.10, 0.20, 0.30, 0.35, 0.40, 0.45, 0.50)
GROUP_DEFINITIONS = {
    "credential_phishing": "Credential or account-access language is present in deterministic content features or rule signals.",
    "government_legal_impersonation": "Government, court, tax, summons, warrant, or legal-pressure evidence is present.",
    "financial_payment_claim": "Financial, payment, banking, invoice, or money-claim evidence is present.",
    "delivery_scam": "Delivery or parcel organization terminology is present.",
    "brand_impersonation": "Recognized-brand claim, lookalike-domain feature, or brand-impersonation rule signal is present.",
    "authentication_passing_phishing": "Retained authentication metadata explicitly reports a pass; this is not inferred from absence.",
    "no_retained_url_evidence": "The private sanitized record retains no URL domain or URL structural evidence.",
    "attachment_led": "Retained attachment metadata indicates an attachment.",
    "short_or_sparse_text": "Sanitized evaluation text is short or has few model tokens.",
    "high_oov_or_lexical_shift": "The model representation has high out-of-vocabulary proportion or low vocabulary coverage.",
    "repeated_campaign_family": "The hashed campaign identifier occurs more than once in the false-negative cohort.",
    "sanitized_limited_context": "Authentication, URL, and attachment context are all absent from the retained sanitized record.",
}
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|javascript|data|file|blob|chrome):[^\s<>]+")
_PATH_RE = re.compile(r"(?i)(?:[A-Za-z]:[\\/]|/Users/|/home/|/tmp/|/var/|file://)[^\s]+")
_HEADER_RE = re.compile(r"(?im)^(?:from|to|cc|bcc|subject|received|message-id|authentication-results|return-path):")
_HTML_RE = re.compile(r"(?is)<\s*/?\s*[a-z][^>]*>")
_SECRET_RE = re.compile(r"(?i)\b(?:api[_ -]?key|admin[_ -]?token|access[_ -]?token|bearer)\s*[:=]\s*[^\s]+")


class ErrorAnalysisValidationError(ValueError):
    """Raised when analysis inputs cannot be validated deterministically."""


def privacy_safe_error_artifact_text(text: str) -> bool:
    """Reject message content and unsafe identifiers from report artifacts."""

    return not any(pattern.search(text) for pattern in (_EMAIL_RE, _URL_RE, _PATH_RE, _HEADER_RE, _HTML_RE, _SECRET_RE))


@dataclass(frozen=True)
class AnalysisObservation:
    sample_id: str
    sample_hash: str
    source_dataset: str
    campaign_id: str
    language: str
    label: str
    probability: float
    features: Mapping[str, int | float | str]
    text_length: int
    token_count: int
    vocabulary_coverage: float | None
    oov_proportion: float | None
    nonzero_features: int | None
    nonzero_selected_features: int | None
    strong_rule_signal_count: int
    rule_signal_count: int
    rule_signal_codes: tuple[str, ...]
    authentication_bucket: str
    url_bucket: str
    sender_domain_category: str
    attachment_category: str
    rule_classification: str = ""
    decision_classification: str = ""
    rule_score: int | None = None
    decision_score: int | None = None
    fusion_performed: bool = False
    safety_floor_applied: bool = False
    missing_evidence_count: int = 0


def _validate_observations(observations: Sequence[AnalysisObservation]) -> None:
    if not observations:
        raise ErrorAnalysisValidationError("No evaluation observations were supplied.")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for observation in observations:
        if observation.sample_id in seen_ids:
            raise ErrorAnalysisValidationError("Duplicate privacy-safe sample ID.")
        if observation.sample_hash in seen_hashes:
            raise ErrorAnalysisValidationError("Duplicate sample hash.")
        if observation.label not in {"safe", "phishing"}:
            raise ErrorAnalysisValidationError("Unsupported evaluation label.")
        if not math.isfinite(float(observation.probability)) or not 0 <= float(observation.probability) <= 1:
            raise ErrorAnalysisValidationError("Invalid model probability.")
        seen_ids.add(observation.sample_id)
        seen_hashes.add(observation.sample_hash)


def stable_observations(observations: Sequence[AnalysisObservation]) -> list[AnalysisObservation]:
    _validate_observations(observations)
    return sorted(observations, key=lambda item: (item.sample_id, item.sample_hash))


def select_false_negatives(observations: Sequence[AnalysisObservation], threshold: float) -> list[AnalysisObservation]:
    stable = stable_observations(observations)
    if not 0 <= float(threshold) <= 1:
        raise ErrorAnalysisValidationError("Threshold must be between 0 and 1.")
    return [item for item in stable if item.label == "phishing" and item.probability < threshold]


def select_true_positives(observations: Sequence[AnalysisObservation], threshold: float) -> list[AnalysisObservation]:
    stable = stable_observations(observations)
    return [item for item in stable if item.label == "phishing" and item.probability >= threshold]


def _stats(values: Sequence[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "mean": None, "median": None, "min": None, "max": None}
    ordered = sorted(float(value) for value in values)
    return {
        "count": len(ordered),
        "mean": float(mean(ordered)),
        "median": float(median(ordered)),
        "min": ordered[0],
        "max": ordered[-1],
    }


def _safe_distribution(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def probability_band_rows(
    observations: Sequence[AnalysisObservation],
    *,
    cohort_name: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total = len(observations)
    for band, lower, upper in THRESHOLD_BANDS:
        members = [item for item in observations if lower <= item.probability < upper]
        rows.append({
            "cohort": cohort_name,
            "band": band,
            "lower_inclusive": lower,
            "upper_exclusive": upper,
            "count": len(members),
            "percentage": (100.0 * len(members) / total) if total else 0.0,
            **{key: value for key, value in _stats([item.probability for item in members]).items() if key != "count"},
            "source_distribution": _safe_distribution([item.source_dataset for item in members]),
            "campaign_distribution": _safe_distribution([item.campaign_id for item in members]),
        })
    return rows


def _present(value: object) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        return value > 0
    return bool(str(value).strip())


def feature_prevalence_rows(observations: Sequence[AnalysisObservation], threshold: float) -> list[dict[str, Any]]:
    stable = stable_observations(observations)
    cohorts = {
        "false_negative": [item for item in stable if item.label == "phishing" and item.probability < threshold],
        "true_positive": [item for item in stable if item.label == "phishing" and item.probability >= threshold],
        "safe": [item for item in stable if item.label == "safe"],
    }
    feature_names = sorted({name for item in stable for name in item.features})
    rows: list[dict[str, Any]] = []
    for name in feature_names:
        counts: dict[str, int] = {}
        prevalences: dict[str, float] = {}
        for cohort, members in cohorts.items():
            count = sum(_present(item.features.get(name)) for item in members)
            counts[cohort] = count
            prevalences[cohort] = count / len(members) if members else 0.0
        rows.append({
            "feature": name,
            "fn_count": counts["false_negative"],
            "fn_prevalence": prevalences["false_negative"],
            "tp_count": counts["true_positive"],
            "tp_prevalence": prevalences["true_positive"],
            "safe_count": counts["safe"],
            "safe_prevalence": prevalences["safe"],
            "fn_minus_tp": prevalences["false_negative"] - prevalences["true_positive"],
            "fn_minus_safe": prevalences["false_negative"] - prevalences["safe"],
        })
    return rows


def _binary_counts(observations: Sequence[AnalysisObservation], threshold: float) -> dict[str, int]:
    tp = sum(item.label == "phishing" and item.probability >= threshold for item in observations)
    fn = sum(item.label == "phishing" and item.probability < threshold for item in observations)
    fp = sum(item.label == "safe" and item.probability >= threshold for item in observations)
    tn = sum(item.label == "safe" and item.probability < threshold for item in observations)
    return {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def threshold_rows(observations: Sequence[AnalysisObservation], thresholds: Sequence[float] = HYPOTHETICAL_THRESHOLDS) -> list[dict[str, Any]]:
    stable = stable_observations(observations)
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        counts = _binary_counts(stable, float(threshold))
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        tpr = recall
        tnr = tn / (tn + fp) if tn + fp else 0.0
        rows.append({
            "hypothetical": True,
            "threshold": float(threshold),
            **counts,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
            "balanced_accuracy": (tpr + tnr) / 2,
        })
    return rows


def calibration_report(observations: Sequence[AnalysisObservation], threshold: float, bin_count: int = 10) -> dict[str, Any]:
    stable = stable_observations(observations)
    bins: list[dict[str, Any]] = []
    weighted_error = 0.0
    for index in range(bin_count):
        lower = index / bin_count
        upper = (index + 1) / bin_count
        members = [item for item in stable if lower <= item.probability < upper or (index == bin_count - 1 and item.probability == 1.0)]
        predicted = [item.probability for item in members]
        observed = [int(item.label == "phishing") for item in members]
        mean_predicted = sum(predicted) / len(predicted) if predicted else None
        observed_rate = sum(observed) / len(observed) if observed else None
        gap = abs(mean_predicted - observed_rate) if mean_predicted is not None and observed_rate is not None else None
        if gap is not None:
            weighted_error += len(members) / len(stable) * gap
        bins.append({
            "bin": f"{lower:.2f}-{upper:.2f}",
            "lower_inclusive": lower,
            "upper_exclusive": upper,
            "count": len(members),
            "mean_predicted_probability": mean_predicted,
            "observed_phishing_rate": observed_rate,
            "absolute_gap": gap,
        })
    false_negatives = select_false_negatives(stable, threshold)
    near = [item for item in false_negatives if threshold - item.probability <= 0.10]
    far = [item for item in false_negatives if threshold - item.probability > 0.10]
    positive = [item for item in stable if item.label == "phishing"]
    negative = [item for item in stable if item.label == "safe"]
    return {
        "method": "fixed reliability bins; no recalibration or fitting",
        "bin_count": bin_count,
        "expected_calibration_error": weighted_error,
        "reliability_bins": bins,
        "false_negative_distance_to_threshold": {
            "near_within_0.10": _stats([threshold - item.probability for item in near]),
            "farther_than_0.10": _stats([threshold - item.probability for item in far]),
        },
        "probability_means_by_observed_label": {
            "phishing": _stats([item.probability for item in positive]),
            "safe": _stats([item.probability for item in negative]),
        },
        "threshold_unchanged": float(threshold),
    }


def group_memberships(observations: Sequence[AnalysisObservation], threshold: float) -> dict[str, list[str]]:
    stable = stable_observations(observations)
    false_negatives = select_false_negatives(stable, threshold)
    repeated_campaigns = {
        campaign for campaign, count in Counter(item.campaign_id for item in false_negatives).items() if count > 1
    }
    memberships: dict[str, list[str]] = defaultdict(list)
    for item in false_negatives:
        names = set(item.features)
        signals = set(getattr(item, "rule_signal_codes", ()))
        has = lambda *keys: any(_present(item.features.get(key)) for key in keys)
        groups: list[str] = []
        if has("credential_request", "account_language") or any("credential" in code or "account_verification" in code for code in signals):
            groups.append("credential_phishing")
        if has("government_claim", "legal_lawsuit", "legal_court", "legal_legal", "legal_summons", "tax_notice", "legal_penalty", "legal_fine", "legal_warrant", "legal_subpoena", "legal_pressure") or any("government" in code or "fear_tactics" in code for code in signals):
            groups.append("government_legal_impersonation")
        if has("financial_claim") or any(any(token in name for token in ("payment", "banking", "financial", "invoice")) for name in names) or any("payment" in code or "banking" in code for code in signals):
            groups.append("financial_payment_claim")
        if has("delivery_claim") or any("delivery" in name for name in names):
            groups.append("delivery_scam")
        if has("technology_claim", "brand_keyword_in_domain", "lookalike_domain") or any("brand" in code or "lookalike" in code for code in signals):
            groups.append("brand_impersonation")
        if item.authentication_bucket == "explicit_pass":
            groups.append("authentication_passing_phishing")
        if item.url_bucket == "no_retained_url_evidence":
            groups.append("no_retained_url_evidence")
        if item.attachment_category != "no_retained_attachment_metadata":
            groups.append("attachment_led")
        if item.text_length < 160 or item.token_count < 25:
            groups.append("short_or_sparse_text")
        if (item.oov_proportion is not None and item.oov_proportion >= 0.50) or (item.vocabulary_coverage is not None and item.vocabulary_coverage < 0.50):
            groups.append("high_oov_or_lexical_shift")
        if item.campaign_id in repeated_campaigns:
            groups.append("repeated_campaign_family")
        if item.authentication_bucket == "absent_from_retained_metadata" and item.url_bucket == "no_retained_url_evidence" and item.attachment_category == "no_retained_attachment_metadata":
            groups.append("sanitized_limited_context")
        for group in groups:
            memberships[group].append(item.sample_id)
    return {key: sorted(value) for key, value in sorted(memberships.items())}


def group_rows(observations: Sequence[AnalysisObservation], threshold: float) -> list[dict[str, Any]]:
    false_negatives = select_false_negatives(observations, threshold)
    memberships = group_memberships(observations, threshold)
    total = len(false_negatives)
    by_id = {item.sample_id: item for item in false_negatives}
    rows: list[dict[str, Any]] = []
    for group, sample_ids in memberships.items():
        members = [by_id[sample_id] for sample_id in sample_ids]
        rows.append({
            "group": group,
            "definition": GROUP_DEFINITIONS[group],
            "count": len(members),
            "percentage_of_false_negatives": 100.0 * len(members) / total if total else 0.0,
            "source_distribution": _safe_distribution([item.source_dataset for item in members]),
            "campaign_distribution": _safe_distribution([item.campaign_id for item in members]),
        })
    return sorted(rows, key=lambda row: (-row["count"], row["group"]))


def shift_summary(observations: Sequence[AnalysisObservation], threshold: float) -> dict[str, Any]:
    stable = stable_observations(observations)

    def rows_for(field: str) -> list[dict[str, Any]]:
        groups: dict[str, list[AnalysisObservation]] = defaultdict(list)
        for item in stable:
            groups[getattr(item, field)].append(item)
        rows: list[dict[str, Any]] = []
        for key in sorted(groups):
            members = groups[key]
            phishing = [item for item in members if item.label == "phishing"]
            rows.append({
                field: key,
                "sample_count": len(members),
                "safe_count": sum(item.label == "safe" for item in members),
                "phishing_count": len(phishing),
                "false_negative_count": sum(item.label == "phishing" and item.probability < threshold for item in members),
                "true_positive_count": sum(item.label == "phishing" and item.probability >= threshold for item in members),
                "false_negative_rate_among_phishing": (sum(item.probability < threshold for item in phishing) / len(phishing)) if phishing else None,
            })
        return rows

    return {
        "source_dataset": rows_for("source_dataset"),
        "campaign_id": rows_for("campaign_id"),
        "language": rows_for("language"),
        "sender_domain_category": rows_for("sender_domain_category"),
        "url_bucket": rows_for("url_bucket"),
        "attachment_category": rows_for("attachment_category"),
        "authentication_bucket": rows_for("authentication_bucket"),
    }


def output_file_hashes(output_dir: str, artifact_names: Sequence[str]) -> dict[str, str]:
    """Return deterministic SHA-256 hashes for named artifacts only."""

    from pathlib import Path

    root = Path(output_dir)
    result: dict[str, str] = {}
    for name in artifact_names:
        path = root / name
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        result[name] = digest.hexdigest()
    return result
