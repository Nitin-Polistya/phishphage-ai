"""Production evaluation and benchmarking harness for PhishShield AI v1.

This script is deliberately evaluation-only.  It loads the registry-selected
production pipeline, never fits or mutates a model, and refuses to turn binary
or inferred annotations into the required three-class ground truth.

Examples::

    python apps/api/scripts/evaluate_v1.py \
      --dataset path/to/evaluation_manifest.json \
      --performance-dataset path/to/eml-directory

The evaluation manifest may contain ``samples`` or be a JSON array.  Every
eligible record must contain ``id``, ``label``, ``source``, ``campaign``,
``date``, and ``expected_class``.  ``raw_email`` supplies RFC822 text;
``input_mode: quick_paste`` accepts structured ``subject``/``body`` fields.
Directories are scanned recursively for .eml/.txt/.json/.jsonl/.csv files.
Sidecar manifests may attach metadata to an .eml using ``path`` or ``file``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Keep the analyzer's offline tldextract cache out of the protected site
# package cache on Windows.  The application itself still owns the same
# offline suffix-list policy; this only makes the read-only runner portable.
os.environ.setdefault(
    "TLDEXTRACT_CACHE",
    str(Path(tempfile.gettempdir()) / "phishshield-evaluation-tld-cache"),
)

ROOT = Path(__file__).resolve().parents[3]
API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.schemas.email import AnalysisInputMode, AnalysisPreviewRequest  # noqa: E402
from app.services.analysis_pipeline import AnalysisPipeline  # noqa: E402


EVALUATOR_VERSION = "1.0.0"
VALID_LABELS = ("safe", "suspicious", "phishing")
REQUIRED_FIELDS = ("id", "label", "source", "campaign", "date", "expected_class")
CATEGORIES = (
    "Microsoft", "Google", "Apple", "Amazon", "PayPal", "Banking",
    "Government", "Shipping", "Social Media", "Business Email", "Newsletters",
    "Marketing", "Receipts", "GitHub", "GitLab", "Developer Services",
    "Education", "Healthcare", "Generic Spam",
)
CSV_FIELDS = [
    "id", "label", "expected_class", "source", "campaign", "date", "category",
    "predicted_class", "risk_score", "phishing_probability", "ml_threshold",
    "rule_score", "decision_safety_state", "presentation_state", "safe_verdict_allowed",
    "triggered_indicators", "evidence_families", "inference_latency_ms",
    "total_processing_time_ms", "status", "error",
]


@dataclass
class Candidate:
    metadata: dict[str, Any]
    raw_email: str | None = None
    request: dict[str, Any] = field(default_factory=dict)
    source_path: str = "<inline>"
    record_index: int = 0


@dataclass
class EvaluationSample:
    id: str
    label: str
    expected_class: str
    source: str
    campaign: str
    date: str
    category: str | None
    raw_email: str | None
    request: dict[str, Any]
    source_path: str


@dataclass
class PerformanceInput:
    raw_email: str | None
    request: dict[str, Any]
    source_path: str


@dataclass
class DatasetLoad:
    candidates: list[Candidate]
    samples: list[EvaluationSample]
    rejected: list[dict[str, Any]]
    input_paths: list[str]


def _json_default(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=_json_default, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _relative_path(path: str | Path) -> str:
    candidate = Path(path)
    try:
        return str(candidate.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return candidate.name or str(candidate)


def _nonempty(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _value(source: Any, key: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return {}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _record_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("samples", "records", "emails", "fixtures", "items"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return [payload]
    return []


def _load_json_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(_read_text(path).splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.extend(_record_list(json.loads(line)))
            except json.JSONDecodeError:
                records.append({"__parse_error__": f"invalid JSON at line {line_number}"})
        return records
    try:
        return _record_list(json.loads(_read_text(path)))
    except json.JSONDecodeError:
        return [{"__parse_error__": "invalid JSON"}]


def _load_csv_records(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _content_from_record(record: dict[str, Any], base_dir: Path) -> tuple[str | None, dict[str, Any]]:
    """Return raw content and an input request without inferring labels."""
    input_mode = str(record.get("input_mode", "raw_email"))
    if "input_mode" not in record and _nonempty(record.get("body")) and not _nonempty(record.get("raw_email")):
        input_mode = AnalysisInputMode.quick_paste.value
    path_value = record.get("path") or record.get("file") or record.get("source_path") or record.get("input_file")
    content_keys = ("raw_email", "raw_text", "email", "email_text", "Email Text", "content", "text", "message", "body_text", "body")
    if path_value and not any(_nonempty(record.get(key)) for key in content_keys):
        target = Path(str(path_value))
        if not target.is_absolute():
            target = base_dir / target
        if target.exists() and target.is_file():
            record = {**record, "__resolved_input_path__": str(target)}
            if target.suffix.lower() in {".json", ".jsonl", ".csv"}:
                return None, {}
            return _read_text(target), {}

    raw_value = next((record.get(key) for key in ("raw_email", "raw_text", "email", "email_text", "Email Text", "content", "text", "message", "body_text") if isinstance(record.get(key), str)), None)
    if raw_value is not None and input_mode != AnalysisInputMode.quick_paste.value:
        return raw_value, {}
    if _nonempty(record.get("body")) or input_mode == AnalysisInputMode.quick_paste.value:
        request = {
            "input_mode": input_mode,
            "raw_email": record.get("raw_email"),
            "sender_name": record.get("sender_name"),
            "sender_email": record.get("sender_email"),
            "recipient_name": record.get("recipient_name"),
            "recipient_email": record.get("recipient_email"),
            "reply_to": record.get("reply_to"),
            "subject": record.get("subject"),
            "body": record.get("body"),
            "attachments": record.get("attachments", []),
        }
        return None, {key: value for key, value in request.items() if value is not None}
    return raw_value, {}


def _sidecar_entries(path: Path, root: Path) -> list[dict[str, Any]]:
    try:
        records = _load_json_records(path)
    except OSError:
        return []
    entries = []
    for record in records:
        if record.get("path") or record.get("file") or record.get("source_path") or record.get("input_file"):
            entries.append(record)
    return entries


def _build_sidecar_index(manifest_paths: Iterable[Path], dataset_root: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for manifest in manifest_paths:
        for entry in _sidecar_entries(manifest, dataset_root):
            path_value = entry.get("path") or entry.get("file") or entry.get("source_path") or entry.get("input_file")
            target = Path(str(path_value))
            if not target.is_absolute():
                target = manifest.parent / target
                if not target.exists():
                    target = dataset_root / str(path_value)
            keys = {str(target.resolve()), str(target), target.name}
            for key in keys:
                index[key] = {key: value for key, value in entry.items() if key not in {"path", "file", "source_path", "input_file"}}
    return index


def _candidate_from_record(record: dict[str, Any], source_path: str, base_dir: Path, index: int, sidecar: dict[str, Any] | None = None) -> Candidate:
    merged = {**(sidecar or {}), **record}
    raw_email, request = _content_from_record(merged, base_dir)
    return Candidate(
        metadata=merged,
        raw_email=raw_email,
        request=request,
        source_path=source_path,
        record_index=index,
    )


def load_dataset(paths: list[Path]) -> DatasetLoad:
    candidates: list[Candidate] = []
    input_paths: list[str] = []
    index = 0
    for source in paths:
        source = source.resolve()
        input_paths.append(_relative_path(source))
        if not source.exists():
            candidates.append(Candidate(metadata={"__missing_path__": str(source)}, source_path=_relative_path(source), record_index=index))
            index += 1
            continue
        files = [source] if source.is_file() else sorted(
            [item for item in source.rglob("*") if item.is_file() and item.suffix.lower() in {".eml", ".txt", ".json", ".jsonl", ".csv"}]
        )
        manifests = [item for item in files if item.suffix.lower() in {".json", ".jsonl"}]
        if source.is_file() and source.suffix.lower() in {".eml", ".txt"}:
            adjacent = [source.with_name(source.name + ".json"), source.with_suffix(".json")]
            manifests.extend(item for item in adjacent if item.exists() and item.is_file())
        sidecar_index = _build_sidecar_index(manifests, source if source.is_dir() else source.parent)
        for file_path in files:
            display = _relative_path(file_path)
            suffix = file_path.suffix.lower()
            if suffix in {".eml", ".txt"}:
                key_options = {str(file_path.resolve()), str(file_path), file_path.name}
                sidecar = next((sidecar_index[key] for key in key_options if key in sidecar_index), None)
                candidate = _candidate_from_record({}, display, file_path.parent, index, sidecar=sidecar)
                candidate.raw_email = _read_text(file_path)
                candidates.append(candidate)
                index += 1
                continue
            if suffix == ".csv":
                records = _load_csv_records(file_path)
            else:
                records = _load_json_records(file_path)
            for record in records:
                path_value = record.get("path") or record.get("file") or record.get("source_path") or record.get("input_file")
                has_inline_content = any(_nonempty(record.get(key)) for key in ("raw_email", "raw_text", "email", "email_text", "Email Text", "content", "text", "message", "body_text", "body"))
                if path_value and not has_inline_content and Path(str(path_value)).suffix.lower() in {".eml", ".txt"}:
                    # This is metadata for a neighboring raw message, not a
                    # second evaluation record.  The raw file is discovered
                    # and joined through sidecar_index above.
                    continue
                candidates.append(_candidate_from_record(record, display, file_path.parent, index))
                index += 1

    samples: list[EvaluationSample] = []
    rejected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for candidate in candidates:
        metadata = candidate.metadata
        missing: list[str] = []
        invalid: list[str] = []
        if "__parse_error__" in metadata:
            invalid.append(str(metadata["__parse_error__"]))
        if "__missing_path__" in metadata:
            invalid.append("input path does not exist")
        for field_name in REQUIRED_FIELDS:
            if not _nonempty(metadata.get(field_name)):
                missing.append(field_name)
        label = str(metadata.get("label", "")).strip()
        expected = str(metadata.get("expected_class", "")).strip()
        if label and label not in VALID_LABELS:
            invalid.append(f"label={label!r} is not one of {VALID_LABELS}")
        if expected and expected not in VALID_LABELS:
            invalid.append(f"expected_class={expected!r} is not one of {VALID_LABELS}")
        if label in VALID_LABELS and expected in VALID_LABELS and label != expected:
            invalid.append("label and expected_class disagree")
        if candidate.raw_email is None and not candidate.request:
            missing.append("input")
        if candidate.request and not _nonempty(candidate.request.get("body")):
            missing.append("body")
        ident = str(metadata.get("id", "")).strip()
        if ident and ident in seen_ids:
            invalid.append("duplicate id")
        if missing or invalid:
            rejected.append({
                "source_path": candidate.source_path,
                "record_index": candidate.record_index,
                "id": ident or None,
                "missing_fields": sorted(set(missing)),
                "invalid_reasons": invalid,
            })
            continue
        seen_ids.add(ident)
        samples.append(EvaluationSample(
            id=ident,
            label=label,
            expected_class=expected,
            source=str(metadata["source"]),
            campaign=str(metadata["campaign"]),
            date=str(metadata["date"]),
            category=str(metadata["category"]) if _nonempty(metadata.get("category")) else None,
            raw_email=candidate.raw_email,
            request=candidate.request,
            source_path=candidate.source_path,
        ))
    return DatasetLoad(candidates=candidates, samples=samples, rejected=rejected, input_paths=input_paths)


def _request_for(sample: EvaluationSample | PerformanceInput) -> AnalysisPreviewRequest | None:
    if sample.request:
        return AnalysisPreviewRequest(**sample.request)
    return None


def _run_pipeline(pipeline: AnalysisPipeline, sample: EvaluationSample | PerformanceInput) -> tuple[Any, dict[str, float], float]:
    started = time.perf_counter()
    request = _request_for(sample)
    result = pipeline.run_request(request) if request is not None else pipeline.run(sample.raw_email or "")
    total_ms = (time.perf_counter() - started) * 1000
    return result, dict(getattr(pipeline, "_last_timings", {})), total_ms


def _signal_details(result: Any) -> list[dict[str, str]]:
    rule = _value(result, "rule_analysis")
    signals = _value(rule, "signals", []) or []
    return [
        {
            "code": str(_value(signal, "code", "")),
            "category": str(_value(signal, "category", "")),
            "severity": str(_enum_value(_value(signal, "severity", ""))),
        }
        for signal in signals
    ]


def _prediction_row(sample: EvaluationSample, result: Any, timings: dict[str, float], total_ms: float) -> dict[str, Any]:
    decision = _value(result, "decision", {})
    ml = _value(result, "ml_analysis", {})
    return {
        "id": sample.id,
        "label": sample.label,
        "expected_class": sample.expected_class,
        "source": sample.source,
        "campaign": sample.campaign,
        "date": sample.date,
        "category": sample.category,
        "predicted_class": str(_enum_value(_value(decision, "classification"))) if _value(decision, "classification") is not None else None,
        "risk_score": _value(decision, "risk_score"),
        "phishing_probability": _value(result, "ml_phishing_probability", _value(ml, "phishing_probability")),
        "ml_threshold": _value(result, "ml_threshold", _value(ml, "decision_threshold")),
        "rule_score": _value(result, "rule_adjusted_score", _value(_value(result, "rule_analysis", {}), "risk_score")),
        "decision_safety_state": str(_enum_value(_value(result, "decision_safety_status"))) if _value(result, "decision_safety_status") is not None else None,
        "presentation_state": str(_enum_value(_value(result, "presentation_state"))) if _value(result, "presentation_state") is not None else None,
        "safe_verdict_allowed": _value(result, "safe_verdict_allowed"),
        "triggered_indicators": [item["code"] for item in _signal_details(result) if item["code"]],
        "indicator_details": _signal_details(result),
        "evidence_families": list(_value(result, "evidence_families", []) or []),
        "inference_latency_ms": timings.get("inference_ms"),
        "total_processing_time_ms": round(total_ms, 3),
        "analysis_completeness_status": str(_enum_value(_value(result, "analysis_completeness_status"))) if _value(result, "analysis_completeness_status") is not None else None,
        "rule_classification": str(_enum_value(_value(_value(result, "rule_analysis", {}), "classification"))) if _value(_value(result, "rule_analysis", {}), "classification") is not None else None,
        "status": "ok",
        "error": None,
    }


def run_evaluation(samples: list[EvaluationSample]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not samples:
        return rows
    pipeline = AnalysisPipeline()
    for sample in samples:
        started = time.perf_counter()
        try:
            result, timings, total_ms = _run_pipeline(pipeline, sample)
            rows.append(_prediction_row(sample, result, timings, total_ms))
        except Exception as error:  # A single malformed record must not stop a collection run.
            rows.append({
                "id": sample.id, "label": sample.label, "expected_class": sample.expected_class,
                "source": sample.source, "campaign": sample.campaign, "date": sample.date,
                "category": sample.category, "predicted_class": None, "risk_score": None,
                "phishing_probability": None, "ml_threshold": None, "rule_score": None,
                "decision_safety_state": None, "presentation_state": None, "safe_verdict_allowed": None,
                "triggered_indicators": [], "indicator_details": [], "evidence_families": [],
                "inference_latency_ms": None,
                "total_processing_time_ms": round((time.perf_counter() - started) * 1000, 3),
                "analysis_completeness_status": None, "rule_classification": None,
                "status": "error", "error": f"{type(error).__name__}: {error}",
            })
    return rows


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _binary_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    tp = sum(row["expected_class"] == "phishing" and row["predicted_class"] == "phishing" for row in rows)
    tn = sum(row["expected_class"] != "phishing" and row["predicted_class"] != "phishing" for row in rows)
    fp = sum(row["expected_class"] != "phishing" and row["predicted_class"] == "phishing" for row in rows)
    fn = sum(row["expected_class"] == "phishing" and row["predicted_class"] != "phishing" for row in rows)
    return {"true_positive": int(tp), "true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn)}


def binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = _binary_counts(rows)
    tp, tn, fp, fn = (counts[key] for key in ("true_positive", "true_negative", "false_positive", "false_negative"))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    fpr = _ratio(fp, fp + tn)
    fnr = _ratio(fn, fn + tp)
    f1 = _ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else None
    return {
        **counts,
        "accuracy": _ratio(tp + tn, len(rows)),
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_score": f1,
        "balanced_accuracy": balanced,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "matthews_correlation_coefficient": mcc,
    }


def probability_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [row for row in rows if isinstance(row.get("phishing_probability"), (int, float))]
    result: dict[str, Any] = {"probability_samples": len(usable), "roc_auc": None, "pr_auc": None, "brier_score": None}
    if not usable:
        result["status"] = "unavailable: no probabilities returned"
        return result
    y_true = [1 if row["expected_class"] == "phishing" else 0 for row in usable]
    probabilities = [float(row["phishing_probability"]) for row in usable]
    if len(set(y_true)) < 2:
        result["status"] = "unavailable: both phishing and non-phishing classes are required"
        return result
    try:
        from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
        result.update({
            "roc_auc": float(roc_auc_score(y_true, probabilities)),
            "pr_auc": float(average_precision_score(y_true, probabilities)),
            "brier_score": float(brier_score_loss(y_true, probabilities)),
            "status": "available",
        })
    except Exception as error:
        result["status"] = f"unavailable: {type(error).__name__}: {error}"
    return result


def _multiclass_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {"classes": list(VALID_LABELS), "confusion_matrix": {}, "per_class": {}}
    for actual in VALID_LABELS:
        result["confusion_matrix"][actual] = {
            predicted: sum(row["expected_class"] == actual and row["predicted_class"] == predicted for row in rows)
            for predicted in VALID_LABELS
        }
    for label in VALID_LABELS:
        tp = sum(row["expected_class"] == label and row["predicted_class"] == label for row in rows)
        fp = sum(row["expected_class"] != label and row["predicted_class"] == label for row in rows)
        fn = sum(row["expected_class"] == label and row["predicted_class"] != label for row in rows)
        support = sum(row["expected_class"] == label for row in rows)
        result["per_class"][label] = {
            "support": support,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "f1_score": _ratio(2 * tp, 2 * tp + fp + fn),
        }
    result["accuracy"] = _ratio(sum(row["expected_class"] == row["predicted_class"] for row in rows), len(rows))
    result["macro_f1"] = _ratio(sum(item["f1_score"] for item in result["per_class"].values() if item["f1_score"] is not None), len(VALID_LABELS))
    return result


def calculate_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [row for row in rows if row.get("status") == "ok" and row.get("predicted_class") in VALID_LABELS]
    binary = binary_metrics(usable) if usable else {key: None for key in ("true_positive", "true_negative", "false_positive", "false_negative", "accuracy", "precision", "recall", "specificity", "f1_score", "balanced_accuracy", "false_positive_rate", "false_negative_rate", "matthews_correlation_coefficient")}
    probabilities = probability_metrics(usable)
    latency = latency_summary(usable)
    metrics = {
        "evaluator_version": EVALUATOR_VERSION,
        "status": "available" if usable else "unavailable: no valid predictions",
        "sample_count": len(usable),
        "failed_inference_count": sum(row.get("status") == "error" for row in rows),
        "binary_phishing_vs_non_phishing": binary,
        "multiclass": _multiclass_metrics(usable) if usable else {"classes": list(VALID_LABELS), "confusion_matrix": {}, "per_class": {}, "accuracy": None, "macro_f1": None},
        "probability_metrics": probabilities,
        "latency": latency,
        # Flat aliases make the report convenient for documentation and
        # dashboards while the nested groups preserve metric semantics.
        "accuracy": binary["accuracy"],
        "precision": binary["precision"],
        "recall": binary["recall"],
        "specificity": binary["specificity"],
        "f1_score": binary["f1_score"],
        "balanced_accuracy": binary["balanced_accuracy"],
        "false_positive_rate": binary["false_positive_rate"],
        "false_negative_rate": binary["false_negative_rate"],
        "matthews_correlation_coefficient": binary["matthews_correlation_coefficient"],
        "roc_auc": probabilities["roc_auc"],
        "pr_auc": probabilities["pr_auc"],
        "average_latency_ms": latency["total_processing_time"]["average_ms"],
        "p95_latency_ms": latency["total_processing_time"]["p95_ms"],
    }
    return metrics


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * p / 100
    lower, upper = int(index), min(int(index) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def latency_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = [float(row["total_processing_time_ms"]) for row in rows if isinstance(row.get("total_processing_time_ms"), (int, float))]
    inference = [float(row["inference_latency_ms"]) for row in rows if isinstance(row.get("inference_latency_ms"), (int, float))]
    def stats(values: list[float]) -> dict[str, Any]:
        return {
            "samples": len(values), "average_ms": statistics.mean(values) if values else None,
            "p95_ms": percentile(values, 95), "p99_ms": percentile(values, 99),
            "min_ms": min(values, default=None), "max_ms": max(values, default=None),
        }
    return {"total_processing_time": stats(total), "inference": stats(inference)}


def calibration(rows: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    usable = [row for row in rows if row.get("status") == "ok" and isinstance(row.get("phishing_probability"), (int, float))]
    bins: list[dict[str, Any]] = []
    for index in range(10):
        lower, upper = index / 10, (index + 1) / 10
        selected = [row for row in usable if lower <= float(row["phishing_probability"]) < upper or (index == 9 and float(row["phishing_probability"]) <= upper)]
        bins.append({
            "bin_lower": lower, "bin_upper": upper, "count": len(selected),
            "mean_probability": statistics.mean(float(row["phishing_probability"]) for row in selected) if selected else None,
            "observed_phishing_rate": statistics.mean(1 if row["expected_class"] == "phishing" else 0 for row in selected) if selected else None,
        })
    result = probability_metrics(usable)
    result.update({"bins": bins, "status": result.get("status", "unavailable")})
    with (output_dir / "calibration_curve.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(bins[0].keys()))
        writer.writeheader(); writer.writerows(bins)
    with (output_dir / "probability_histogram.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle); writer.writerow(["bin_lower", "bin_upper", "count"])
        writer.writerows([[item["bin_lower"], item["bin_upper"], item["count"]] for item in bins])
    _write_svg(output_dir / "reliability_diagram.svg", bins, "Reliability diagram", y_key="observed_phishing_rate", diagonal=True)
    _write_svg(output_dir / "calibration_curve.svg", bins, "Calibration curve", y_key="observed_phishing_rate", diagonal=True)
    _write_histogram_svg(output_dir / "probability_histogram.svg", bins)
    return result


def _write_svg(path: Path, bins: list[dict[str, Any]], title: str, y_key: str, diagonal: bool) -> None:
    width, height, left, top, plot = 640, 440, 70, 50, 330
    points = []
    for item in bins:
        if item["mean_probability"] is not None and item[y_key] is not None:
            x = left + float(item["mean_probability"]) * plot
            y = top + plot - float(item[y_key]) * plot
            points.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(points)
    diagonal_line = f'<line x1="{left}" y1="{top + plot}" x2="{left + plot}" y2="{top}" stroke="#999" stroke-dasharray="5,5" />' if diagonal else ""
    content = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="white"/><text x="{left}" y="25" font-family="sans-serif" font-size="18">{title}</text>
<line x1="{left}" y1="{top + plot}" x2="{left + plot}" y2="{top + plot}" stroke="#222"/><line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot}" stroke="#222"/>{diagonal_line}
<text x="{left + 110}" y="{top + plot + 42}" font-family="sans-serif">Mean predicted probability</text><text transform="translate(18 {top + 220}) rotate(-90)" font-family="sans-serif">Observed phishing rate</text>
{f'<polyline points="{polyline}" fill="none" stroke="#1261a0" stroke-width="3"/>' if polyline else '<text x="100" y="220" font-family="sans-serif">No eligible probability samples</text>'}
</svg>'''
    path.write_text(content, encoding="utf-8")


def _write_histogram_svg(path: Path, bins: list[dict[str, Any]]) -> None:
    width, height, left, top, plot = 640, 440, 70, 50, 330
    maximum = max((item["count"] for item in bins), default=0) or 1
    bars = []
    for index, item in enumerate(bins):
        bar_width = plot / 10 - 4
        bar_height = item["count"] / maximum * plot
        x = left + index * plot / 10 + 2
        y = top + plot - bar_height
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" fill="#1261a0"/>')
    path.write_text(f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="white"/><text x="{left}" y="25" font-family="sans-serif" font-size="18">Probability histogram</text><line x1="{left}" y1="{top + plot}" x2="{left + plot}" y2="{top + plot}" stroke="#222"/><line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot}" stroke="#222"/>{''.join(bars)}<text x="{left + 130}" y="{top + plot + 35}" font-family="sans-serif">Phishing probability</text></svg>''', encoding="utf-8")


def _error_explanation(row: dict[str, Any], error_type: str) -> dict[str, Any]:
    probability = row.get("phishing_probability")
    threshold = row.get("ml_threshold")
    indicators = list(row.get("triggered_indicators", []))
    families = list(row.get("evidence_families", []))
    if error_type == "false_negative":
        reasons = []
        if isinstance(probability, (int, float)) and isinstance(threshold, (int, float)) and probability < threshold:
            reasons.append("model_probability_below_threshold")
        if isinstance(row.get("rule_score"), (int, float)) and row["rule_score"] < 60:
            reasons.append("rule_score_below_phishing_floor")
        if not indicators:
            reasons.append("no_triggered_rule_indicators")
        why = "False negative: the final class was not phishing. " + ("; ".join(reasons) if reasons else "the fused decision did not reach phishing") + "."
        unexpected = []
    else:
        why = "False positive: the final class was phishing for a non-phishing ground-truth sample; observed indicators and probability supported an alert under the unchanged policy."
        reasons = []
        unexpected = indicators
    missing = reasons if error_type == "false_negative" else []
    return {
        "error_type": error_type,
        "why_failed": why,
        "missing_indicators": json.dumps(missing),
        "unexpected_indicators": json.dumps(unexpected),
        "model_probability": probability,
        "rule_score": row.get("rule_score"),
        "decision_safety_state": row.get("decision_safety_state"),
        "evidence_families": json.dumps(families),
    }


def _safety_review(row: dict[str, Any]) -> dict[str, str]:
    details = row.get("indicator_details", [])
    codes = {item.get("code", "") for item in details}
    families = {str(item) for item in row.get("evidence_families", [])}
    def presence(keys: Iterable[str]) -> bool:
        return any(any(key in code for key in keys) for code in codes)
    rule_class = row.get("rule_classification")
    if rule_class == "phishing":
        rules = "yes"
    elif rule_class == "suspicious":
        rules = "partial: rules raised suspicion but not phishing"
    else:
        rules = "no"
    url = "yes" if "url" in families or presence(("url", "mailto")) else "no"
    identity = "yes" if "identity" in families or presence(("identity", "brand", "sender_domain")) else "no"
    header = "yes" if "authentication" in families or presence(("header", "auth", "spf", "dkim", "dmarc")) else "no"
    safety = "yes: review/rescan state could prevent a reassuring safe presentation" if row.get("decision_safety_state") != "eligible" else "no: safety layer does not convert a non-phishing class into phishing"
    available_families = [name for name in ("url", "identity", "authentication") if name in families]
    generalizable = "candidate only: requires the same evidence across at least two independent campaigns" if available_families else "no: this sample alone does not justify a deterministic rule"
    return {
        "could_rules_have_caught_it": rules,
        "could_url_analysis_have_caught_it": url,
        "could_identity_analysis_have_caught_it": identity,
        "could_header_analysis_have_caught_it": header,
        "could_decision_safety_have_caught_it": safety,
        "would_new_deterministic_rule_improve_recall": generalizable,
    }


def error_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    usable = [row for row in rows if row.get("status") == "ok" and row.get("predicted_class") in VALID_LABELS]
    groups: dict[str, list[dict[str, Any]]] = {"true_positives": [], "true_negatives": [], "false_positives": [], "false_negatives": []}
    for row in usable:
        if row["expected_class"] == "phishing" and row["predicted_class"] == "phishing":
            groups["true_positives"].append(row)
        elif row["expected_class"] != "phishing" and row["predicted_class"] != "phishing":
            groups["true_negatives"].append(row)
        elif row["predicted_class"] == "phishing":
            groups["false_positives"].append({**row, **_error_explanation(row, "false_positive")})
        else:
            groups["false_negatives"].append({**row, **_error_explanation(row, "false_negative"), **_safety_review(row)})
    return groups


def category_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("category"):
            groups[str(row["category"])].append(row)
    categories = list(CATEGORIES) + sorted(set(groups) - set(CATEGORIES))
    result = []
    for category in categories:
        usable = [row for row in groups.get(category, []) if row.get("status") == "ok" and row.get("predicted_class") in VALID_LABELS]
        metrics = binary_metrics(usable) if usable else {}
        result.append({"category": category, "status": "available" if usable else "unavailable", "sample_count": len(usable), "reason": None if usable else "No eligible labeled samples with this exact category value.", **metrics})
    return result


def _write_rows(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    fields = fields or (list(rows[0].keys()) if rows else ["id"])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(row.get(key), sort_keys=True) if isinstance(row.get(key), (list, dict)) else row.get(key) for key in fields})


def _load_performance_inputs(paths: list[Path]) -> list[PerformanceInput]:
    inputs: list[PerformanceInput] = []
    for source in paths:
        source = source.resolve()
        files = [source] if source.is_file() else sorted([item for item in source.rglob("*") if item.is_file() and item.suffix.lower() in {".eml", ".txt", ".json", ".jsonl", ".csv"}])
        for file_path in files:
            suffix = file_path.suffix.lower()
            if suffix in {".eml", ".txt"}:
                inputs.append(PerformanceInput(_read_text(file_path), {}, _relative_path(file_path)))
            elif suffix == ".csv":
                records = _load_csv_records(file_path)
                for record in records:
                    raw, request = _content_from_record(record, file_path.parent)
                    if raw or request:
                        inputs.append(PerformanceInput(raw, request, _relative_path(file_path)))
            else:
                for record in _load_json_records(file_path):
                    raw, request = _content_from_record(record, file_path.parent)
                    if raw or request:
                        inputs.append(PerformanceInput(raw, request, _relative_path(file_path)))
    return inputs


def _resource_snapshot() -> dict[str, Any]:
    try:
        import psutil
        process = psutil.Process()
        return {"rss_mb": process.memory_info().rss / (1024 * 1024), "cpu_percent": process.cpu_percent(None), "available": True}
    except Exception as error:
        return {"rss_mb": None, "cpu_percent": None, "available": False, "reason": f"{type(error).__name__}: {error}"}


def _cpu_seconds() -> float | None:
    try:
        import psutil
        times = psutil.Process().cpu_times()
        return float(times.user + times.system)
    except Exception:
        return None


def _cold_child(path: Path) -> int:
    started = time.perf_counter()
    cpu_before = _cpu_seconds()
    try:
        pipeline = AnalysisPipeline()
        result, timings, total_ms = _run_pipeline(pipeline, PerformanceInput(_read_text(path), {}, str(path)))
        elapsed = max(time.perf_counter() - started, 1e-9)
        resource = _resource_snapshot()
        cpu_after = _cpu_seconds()
        if cpu_before is not None and cpu_after is not None:
            resource["cpu_percent"] = (cpu_after - cpu_before) / elapsed * 100
        payload = {"status": "ok", "startup_plus_first_inference_ms": round(elapsed * 1000, 3), "pipeline_total_ms": round(total_ms, 3), "inference_ms": timings.get("inference_ms"), "model_version": _value(_value(result, "ml_analysis", {}), "model_version"), "resource": resource}
    except Exception as error:
        payload = {"status": "error", "error": f"{type(error).__name__}: {error}", "startup_plus_first_inference_ms": round((time.perf_counter() - started) * 1000, 3)}
    print(json.dumps(payload, allow_nan=False))
    return 0 if payload["status"] == "ok" else 1


def benchmark(performance_inputs: list[PerformanceInput], args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    if not performance_inputs:
        unavailable = {"status": "unavailable", "reason": "No performance inputs were supplied or readable."}
        return unavailable, unavailable
    representative = performance_inputs[0]
    cold: list[dict[str, Any]] = []
    if representative.raw_email is not None:
        with tempfile.TemporaryDirectory(prefix="phishshield-eval-") as temporary:
            path = Path(temporary) / "representative.eml"
            path.write_text(representative.raw_email, encoding="utf-8")
            for _ in range(args.cold_repetitions):
                completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--cold-child", str(path)], capture_output=True, text=True, timeout=120)
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                if lines:
                    try: cold.append(json.loads(lines[-1]))
                    except json.JSONDecodeError: cold.append({"status": "error", "error": "cold child returned invalid JSON"})
                else:
                    cold.append({"status": "error", "error": completed.stderr[-500:] or "cold child returned no output"})
    else:
        cold = [{"status": "unavailable", "reason": "Structured quick-paste performance inputs cannot be isolated through the raw-email child path."}]

    pipeline = AnalysisPipeline()
    prepare_started = time.perf_counter()
    try:
        prepare = pipeline.prepare()
    except Exception as error:
        prepare = {"status": "error", "error": f"{type(error).__name__}: {error}"}
    warm_total: list[float] = []
    warm_inference: list[float] = []
    warm_errors = 0
    before = _resource_snapshot()
    cpu_before = _cpu_seconds()
    cpu_started = time.perf_counter()
    try:
        for _ in range(args.warm_repetitions):
            for item in performance_inputs:
                try:
                    _, timings, total_ms = _run_pipeline(pipeline, item)
                    warm_total.append(total_ms)
                    if isinstance(timings.get("inference_ms"), (int, float)):
                        warm_inference.append(float(timings["inference_ms"]))
                except Exception:
                    warm_errors += 1
    finally:
        after = _resource_snapshot()
    wall_seconds = max(time.perf_counter() - cpu_started, 1e-9)
    cpu_after = _cpu_seconds()
    cpu_percent = ((cpu_after - cpu_before) / wall_seconds * 100) if cpu_before is not None and cpu_after is not None else None
    def stats(values: list[float]) -> dict[str, Any]:
        return {"samples": len(values), "average_ms": statistics.mean(values) if values else None, "p95_ms": percentile(values, 95), "p99_ms": percentile(values, 99), "min_ms": min(values, default=None), "max_ms": max(values, default=None)}
    warm = {"status": "available" if warm_total else "unavailable", "input_count": len(performance_inputs), "repetitions": args.warm_repetitions, "total_processing": stats(warm_total), "inference": stats(warm_inference), "errors": warm_errors, "prepare_ms": round((time.perf_counter() - prepare_started) * 1000, 3), "prepare": prepare, "resource_before": before, "resource_after": after, "cpu_usage_percent": cpu_percent, "wall_seconds": wall_seconds}
    benchmark_json = {"evaluator_version": EVALUATOR_VERSION, "status": "available" if warm_total else "unavailable", "cold_start": {"repetitions": args.cold_repetitions, "samples": cold}, "warm_start": warm, "input_provenance": sorted(set(item.source_path for item in performance_inputs)), "quality_metrics_excluded": True, "limitations": ["Cold start measures a fresh Python child process for one representative raw RFC822 input.", "Resource counters are process-local and are not a capacity claim.", "Performance-only inputs are never used as ground truth or quality metrics."]}
    latency = {"evaluation": latency_summary([]), "benchmark_warm_start": {"total_processing": warm["total_processing"], "inference": warm["inference"]}, "benchmark_cold_start": {"startup_plus_first_inference_ms": stats([float(item["startup_plus_first_inference_ms"]) for item in cold if isinstance(item.get("startup_plus_first_inference_ms"), (int, float))]), "inference": stats([float(item["inference_ms"]) for item in cold if isinstance(item.get("inference_ms"), (int, float))])}}
    return benchmark_json, latency


def _recommendations(metrics: dict[str, Any], groups: dict[str, list[dict[str, Any]]], load: DatasetLoad) -> tuple[str, str]:
    missing_counts = Counter(field for item in load.rejected for field in item.get("missing_fields", []))
    invalid_counts = Counter(reason for item in load.rejected for reason in item.get("invalid_reasons", []))
    lines = ["# Recommendations", "", "This report is observational. No model, threshold, calibration, rule, dataset, label, deployment, or production feature was changed.", ""]
    if not load.samples:
        lines += ["## Quality evaluation is blocked", "", "No sample satisfied the strict ground-truth contract, so no accuracy, error, category, calibration, or safety recommendation is presented as a measured model result.", "", "Missing ground-truth fields by rejected record:", ""]
        for field_name, count in sorted(missing_counts.items()): lines.append(f"- `{field_name}`: {count} record(s)")
        for reason, count in sorted(invalid_counts.items()): lines.append(f"- invalid annotation: `{reason}` ({count} record(s))")
        lines += ["", "Provide a reviewer-approved manifest with exact three-class labels and campaign/date metadata. Do not map `0/1`, spam, scam, or filename conventions automatically."]
    elif metrics.get("sample_count", 0) == 0:
        lines += ["## Quality evaluation is unavailable", "", "Ground-truth samples were admitted, but no production prediction completed successfully. Review the inference errors before interpreting any quality metric.", "", f"Failed inference count: `{metrics.get('failed_inference_count', 0)}`."]
    else:
        binary = metrics["binary_phishing_vs_non_phishing"]
        if binary.get("false_negative", 0): lines += [f"- Review {binary['false_negative']} false negative(s) across independent campaigns before considering any deterministic rule."]
        else: lines += ["- No false negative was observed in the eligible sample; this is not evidence of general recall without representative campaign coverage."]
        lines += ["- Keep the current threshold and calibration unchanged unless a larger, campaign-grouped evaluation establishes a reproducible trade-off.", "- Treat category rows with no exact category metadata as unavailable rather than imputing a category."]
    lines += ["", "## Measurement limitations", "", "- Category benchmarks require an explicit `category` field; categories are never inferred from sender names or subject text.", "- A safe or suspicious classification is considered non-phishing for binary safety metrics; three-class metrics remain separate.", "- Error explanations describe observable production evidence, not hidden intent annotations."]
    recommendation = "\n".join(lines) + "\n"
    next_lines = ["# NEXT_IMPROVEMENTS", "", "Prioritized work is listed for review only; this pass does not implement improvements.", "", "| Priority | Recommendation | Expected impact | Risk | Engineering effort | Potential overfitting |", "| --- | --- | --- | --- | --- | --- |"]
    next_lines.append("| P0 | Add a reviewer-approved, campaign-grouped manifest containing all required fields and all three classes. | High | Low | Medium | Low |")
    next_lines.append("| P1 | Expand exact category coverage across the requested provider, industry, and message-type families. | High | Low | High | Low if campaign-grouped |")
    if groups.get("false_negatives"):
        next_lines.append("| P1 | Review false negatives across at least two independent campaigns before proposing a deterministic rule. | Medium/High | Medium | Medium | Medium |")
    else:
        next_lines.append("| P1 | Re-run false-negative safety analysis after valid phishing labels are available. | High | Low | Low | Low |")
    next_lines.append("| P2 | Repeat cold/warm resource measurements on a dedicated worker with deployment-class process limits. | Medium | Low | Medium | Low |")
    next_lines.append("| P3 | Revisit thresholds or calibration only after the evidence gate is met; no change is justified by an incomplete set. | Unknown | High | High | High |")
    return recommendation, "\n".join(next_lines) + "\n"


def report_dataset_status(load: DatasetLoad) -> dict[str, Any]:
    missing_by_field = Counter(field for item in load.rejected for field in item.get("missing_fields", []))
    invalid = Counter(reason for item in load.rejected for reason in item.get("invalid_reasons", []))
    per_path: dict[str, dict[str, Any]] = defaultdict(lambda: {"records": 0, "missing_fields": Counter(), "invalid_reasons": Counter()})
    for item in load.rejected:
        entry = per_path[item["source_path"]]; entry["records"] += 1
        entry["missing_fields"].update(item.get("missing_fields", [])); entry["invalid_reasons"].update(item.get("invalid_reasons", []))
    return {
        "input_paths": load.input_paths, "discovered_records": len(load.candidates), "eligible_samples": len(load.samples), "rejected_records": len(load.rejected),
        "missing_fields": dict(sorted(missing_by_field.items())), "invalid_reasons": dict(sorted(invalid.items())),
        "by_source_path": {path: {"records": value["records"], "missing_fields": dict(value["missing_fields"]), "invalid_reasons": dict(value["invalid_reasons"])} for path, value in sorted(per_path.items())},
        "contract": {"required_fields": list(REQUIRED_FIELDS), "supported_labels": list(VALID_LABELS), "label_expected_class_must_match": True, "raw_content_is_not_written_to_reports": True},
    }


def write_reports(output_dir: Path, load: DatasetLoad, rows: list[dict[str, Any]], args: argparse.Namespace) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_status = report_dataset_status(load)
    usable = [row for row in rows if row.get("status") == "ok" and row.get("predicted_class") in VALID_LABELS]
    metrics = calculate_metrics(rows)
    calibration_report = calibration(rows, output_dir)
    metrics["calibration"] = calibration_report
    groups = error_rows(rows)
    categories = category_metrics(rows)
    performance_inputs = _load_performance_inputs([Path(item) for item in args.performance_dataset]) if args.performance_dataset else [PerformanceInput(sample.raw_email, sample.request, sample.source_path) for sample in load.samples]
    if args.performance_limit and args.performance_limit > 0:
        performance_inputs = performance_inputs[:args.performance_limit]
    benchmark_json, benchmark_latency = benchmark(performance_inputs, args)
    latency = {"evaluation": latency_summary(usable), **benchmark_latency}
    write_json(output_dir / "metrics.json", {"dataset": dataset_status, **metrics})
    write_json(output_dir / "benchmark.json", benchmark_json)
    write_json(output_dir / "latency.json", latency)
    _write_rows(output_dir / "predictions.csv", rows, CSV_FIELDS)
    with (output_dir / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows: handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    confusion_rows = [{"actual": actual, "predicted": predicted, "count": sum(row["expected_class"] == actual and row["predicted_class"] == predicted for row in usable)} for actual in VALID_LABELS for predicted in VALID_LABELS]
    _write_rows(output_dir / "confusion_matrix.csv", confusion_rows, ["actual", "predicted", "count"])
    error_fields = list(dict.fromkeys(CSV_FIELDS + ["error_type", "why_failed", "missing_indicators", "unexpected_indicators", "model_probability", "could_rules_have_caught_it", "could_url_analysis_have_caught_it", "could_identity_analysis_have_caught_it", "could_header_analysis_have_caught_it", "could_decision_safety_have_caught_it", "would_new_deterministic_rule_improve_recall"]))
    for name, key in (("true_positives.csv", "true_positives"), ("true_negatives.csv", "true_negatives"), ("false_positives.csv", "false_positives"), ("false_negatives.csv", "false_negatives")):
        _write_rows(output_dir / name, groups[key], error_fields)
    _write_rows(output_dir / "safety_review.csv", groups["false_negatives"], ["id", "source", "campaign", "date", "predicted_class", "phishing_probability", "rule_score", "decision_safety_state", "could_rules_have_caught_it", "could_url_analysis_have_caught_it", "could_identity_analysis_have_caught_it", "could_header_analysis_have_caught_it", "could_decision_safety_have_caught_it", "would_new_deterministic_rule_improve_recall"])
    category_fields = ["category", "status", "sample_count", "reason", "true_positive", "true_negative", "false_positive", "false_negative", "accuracy", "precision", "recall", "specificity", "f1_score", "balanced_accuracy", "false_positive_rate", "false_negative_rate", "matthews_correlation_coefficient"]
    _write_rows(output_dir / "category_metrics.csv", categories, category_fields)
    recommendations, next_improvements = _recommendations(metrics, groups, load)
    (output_dir / "recommendations.md").write_text(recommendations, encoding="utf-8")
    (output_dir / "NEXT_IMPROVEMENTS.md").write_text(next_improvements, encoding="utf-8")
    binary = metrics["binary_phishing_vs_non_phishing"]
    summary_lines = [
        "# PhishShield AI v1.0.0 Evaluation Summary", "", f"Evaluator version: `{EVALUATOR_VERSION}`", f"Generated: `{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}`", "", "## Ground-truth gate", "", f"- Discovered records: **{len(load.candidates)}**", f"- Eligible records: **{len(load.samples)}**", f"- Rejected records: **{len(load.rejected)}**", f"- Supported labels: `{', '.join(VALID_LABELS)}`", "", "The runner does not infer labels, dates, campaigns, or categories. Rejected records remain outside every metric.", ""]
    if load.rejected:
        summary_lines += ["### Missing or invalid data", ""]
        for field_name, count in sorted(dataset_status["missing_fields"].items()): summary_lines.append(f"- Missing `{field_name}`: {count} record(s)")
        for reason, count in sorted(dataset_status["invalid_reasons"].items()): summary_lines.append(f"- Invalid annotation: `{reason}` ({count} record(s))")
        summary_lines.append("")
    summary_lines += ["## Measured quality", ""]
    if usable:
        summary_lines += [f"- Accuracy: `{binary.get('accuracy')}`", f"- Precision (phishing vs non-phishing): `{binary.get('precision')}`", f"- Recall: `{binary.get('recall')}`", f"- Specificity: `{binary.get('specificity')}`", f"- F1: `{binary.get('f1_score')}`", f"- Balanced accuracy: `{binary.get('balanced_accuracy')}`", f"- FPR: `{binary.get('false_positive_rate')}`", f"- FNR: `{binary.get('false_negative_rate')}`", f"- MCC: `{binary.get('matthews_correlation_coefficient')}`", f"- ROC AUC: `{metrics['probability_metrics'].get('roc_auc')}`", f"- PR AUC: `{metrics['probability_metrics'].get('pr_auc')}`", ""]
    elif load.samples:
        summary_lines += ["No quality prediction completed successfully; inspect inference errors before interpreting metrics.", ""]
    else:
        summary_lines += ["Quality metrics are unavailable because no record passed the ground-truth and input contract.", ""]
    summary_lines += ["## Performance", "", f"- Performance benchmark status: `{benchmark_json.get('status')}`", f"- Performance inputs: `{len(performance_inputs)}`", "- See `benchmark.json` and `latency.json` for cold start, warm start, average, P95, P99, memory, and CPU measurements.", "", "## Calibration", "", f"- Calibration status: `{calibration_report.get('status')}`", f"- Brier score: `{calibration_report.get('brier_score')}`", "- No calibration or threshold was changed.", "", "## Safety and limitations", "", f"- False positives: `{len(groups['false_positives'])}`", f"- False negatives: `{len(groups['false_negatives'])}`", "- False-negative safety review is in `false_negatives.csv` and `safety_review.csv`.", "- Raw email bodies, URLs, headers, and attachment contents are not written to reports.", "- Results are not a deployment decision and do not authorize threshold changes, retraining, or release.", ""]
    (output_dir / "summary.md").write_text("\n".join(summary_lines), encoding="utf-8")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", action="append", default=[], help="Evaluation file or directory; repeatable.")
    parser.add_argument("--raw-email-text", help="One raw RFC822 sample; use with --metadata.")
    parser.add_argument("--raw-email-file", type=Path, help="One raw RFC822 file; use with --metadata.")
    parser.add_argument("--metadata", type=Path, help="JSON object containing required ground-truth fields for one raw input.")
    parser.add_argument("--performance-dataset", action="append", default=[], help="Optional performance-only file/directory. It need not have labels; it is never used for quality metrics.")
    parser.add_argument("--performance-limit", type=int, default=0, help="Limit performance inputs; 0 means all.")
    parser.add_argument("--cold-repetitions", type=int, default=3)
    parser.add_argument("--warm-repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "evaluation")
    parser.add_argument("--strict", action="store_true", help="Return nonzero when records are rejected or no eligible samples exist.")
    parser.add_argument("--cold-child", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.cold_child:
        return args
    if args.raw_email_text and args.raw_email_file:
        parser.error("use only one of --raw-email-text and --raw-email-file")
    if args.metadata and not (args.raw_email_text or args.raw_email_file):
        parser.error("--metadata requires --raw-email-text or --raw-email-file")
    if args.cold_repetitions < 1 or args.warm_repetitions < 1:
        parser.error("repetition counts must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if args.cold_child:
        return _cold_child(args.cold_child)
    dataset_paths = [Path(item) for item in args.dataset]
    load = load_dataset(dataset_paths)
    if args.raw_email_text or args.raw_email_file:
        metadata: dict[str, Any] = {}
        if args.metadata:
            metadata = json.loads(_read_text(args.metadata))
            if not isinstance(metadata, dict):
                raise ValueError("--metadata must contain one JSON object")
        content = args.raw_email_text if args.raw_email_text is not None else _read_text(args.raw_email_file)
        candidate = Candidate(metadata=metadata, raw_email=content, source_path="<inline>", record_index=0)
        load.candidates.append(candidate)
        # Reuse strict validation without a second ingestion format.
        metadata = candidate.metadata
        missing = [field_name for field_name in REQUIRED_FIELDS if not _nonempty(metadata.get(field_name))]
        invalid = []
        if metadata.get("label") not in VALID_LABELS: invalid.append("label is missing or unsupported")
        if metadata.get("expected_class") not in VALID_LABELS: invalid.append("expected_class is missing or unsupported")
        if metadata.get("label") in VALID_LABELS and metadata.get("expected_class") in VALID_LABELS and metadata["label"] != metadata["expected_class"]: invalid.append("label and expected_class disagree")
        if missing or invalid:
            load.rejected.append({"source_path": "<inline>", "record_index": 0, "id": metadata.get("id"), "missing_fields": missing, "invalid_reasons": invalid})
        else:
            load.candidates.append(candidate)
            load.samples.append(EvaluationSample(str(metadata["id"]), str(metadata["label"]), str(metadata["expected_class"]), str(metadata["source"]), str(metadata["campaign"]), str(metadata["date"]), str(metadata["category"]) if metadata.get("category") else None, content, {}, "<inline>"))
        load.input_paths.append("<inline>")
    write_reports(args.output, load, run_evaluation(load.samples), args)
    print(json.dumps({"output": str(args.output), "discovered_records": len(load.candidates), "eligible_samples": len(load.samples), "rejected_records": len(load.rejected)}, sort_keys=True))
    if args.strict and (load.rejected or not load.samples):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
