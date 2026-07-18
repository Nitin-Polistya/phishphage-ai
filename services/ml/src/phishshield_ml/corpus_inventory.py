"""Deterministic, privacy-preserving corpus inventory and leakage checks."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .dataset import canonicalize_template
from .generalization import _hamming, _simhash
from .preprocessing import normalize_email_text


PROVENANCE_FIELDS = (
    "sample_id", "label", "source_name", "source_record_id",
    "source_url_or_reference", "source_license", "acquisition_date", "language",
    "is_synthetic", "is_targeted_synthetic", "campaign_group", "template_group",
    "message_type", "brand_family", "delivery_provider", "sender_domain",
    "contains_urls", "contains_attachments", "split", "external_evaluation_only",
    "content_hash", "normalized_content_hash", "notes",
)
ACTIVE_BOUNDARIES = {
    "development_pool": "data/processed/english_core_v3.csv",
    "grouped_diagnostic": "data/processed/grouped_template_diagnostic_v2.csv",
    "external_development": "data/external/development_benchmark.csv",
    "external_final": "data/external/final_external_benchmark.csv",
}
URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
SUBJECT_RE = re.compile(r"(?im)^subject\s*:\s*(.+)$")
TRAINING_SPLITS = {"development_pool", "train", "validation", "test", "grouped_diagnostic"}
EXTERNAL_SPLITS = {"external", "external_development", "external_final"}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _nullable(value: Any) -> Any:
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return text or None


def _boolean(value: Any) -> bool | None:
    if value is None or pd.isna(value):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    return None


def _registry_index(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "dataset_sources.json"
    if not path.exists():
        return {}
    sources = json.loads(path.read_text(encoding="utf-8"))["sources"]
    aliases = {
        "zenodo-social-engineering-15235123": "zenodo_phishing_nlp_15235123",
        "zenodo-validation-13474746": "zenodo_phishing_validation_13474746",
    }
    index = {source["id"]: source for source in sources}
    for alias, source_id in aliases.items():
        index[alias] = index[source_id]
    return index


def normalize_record(
    row: dict[str, Any], split: str, index: int, registry: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Map an existing row into the standard metadata schema without exporting content."""
    text = normalize_email_text(str(row.get("text") or ""))
    source_name = str(row.get("source_name") or row.get("source") or "unspecified")
    source = (registry or {}).get(source_name, {})
    provenance = str(_nullable(row.get("provenance_type")) or "").lower()
    synthetic = _boolean(row.get("is_synthetic"))
    if synthetic is None and provenance.startswith("synthetic"):
        synthetic = True
    elif synthetic is None and provenance == "real_or_curated":
        synthetic = False
    targeted = _boolean(row.get("is_targeted_synthetic"))
    if targeted is None and synthetic is True:
        targeted = "targeted" in provenance or "targeted" in source_name
    elif targeted is None and synthetic is False:
        targeted = False
    content_hash = _hash(text)
    normalized_hash = _hash(canonicalize_template(text))
    template_group = _nullable(row.get("template_group"))
    campaign_group = _nullable(row.get("campaign_group"))
    subject = SUBJECT_RE.search(text)
    subject_key = _hash(canonicalize_template(subject.group(1))) if subject else None
    external = (
        split in EXTERNAL_SPLITS
        or bool(_boolean(row.get("external_evaluation_only")))
        or source.get("role") == "external_validation_only"
    )
    sender_domain = _nullable(row.get("sender_domain"))
    if sender_domain and "@" in sender_domain:
        sender_domain = sender_domain.rsplit("@", 1)[-1].lower()
    record = {
        "sample_id": str(row.get("sample_id") or f"{split}:{content_hash[:20]}"),
        "label": int(row["label"]),
        "source_name": source_name,
        "source_record_id": _nullable(row.get("source_record_id")),
        "source_url_or_reference": _nullable(row.get("source_url_or_reference")) or source.get("official_page"),
        "source_license": _nullable(row.get("source_license")) or source.get("license"),
        "acquisition_date": _nullable(row.get("acquisition_date")),
        "language": str(row.get("language") or "unknown").lower(),
        "is_synthetic": synthetic,
        "is_targeted_synthetic": targeted,
        "campaign_group": campaign_group,
        "template_group": template_group,
        "message_type": _nullable(row.get("message_type")) or _nullable(row.get("scenario")),
        "brand_family": _nullable(row.get("brand_family")),
        "delivery_provider": _nullable(row.get("delivery_provider")),
        "sender_domain": sender_domain,
        "contains_urls": _boolean(row.get("contains_urls")) if "contains_urls" in row else bool(URL_RE.search(text)),
        "contains_attachments": _boolean(row.get("contains_attachments")),
        "split": split,
        "external_evaluation_only": external,
        "content_hash": content_hash,
        "normalized_content_hash": normalized_hash,
        "notes": _nullable(row.get("notes")),
        "_subject_key": subject_key,
        "_semantic_fingerprint": _nullable(row.get("semantic_fingerprint")) or f"{_simhash(text):016x}",
        "_original_campaign_missing": campaign_group is None,
        "_original_template_missing": template_group is None,
    }
    return record


def load_boundary_records(root: Path, boundaries: dict[str, str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    registry = _registry_index(root)
    records: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    for split, relative in sorted((boundaries or ACTIVE_BOUNDARIES).items()):
        path = root / relative
        if not path.exists():
            files.append({"path": relative, "boundary": split, "status": "missing", "rows": 0, "columns": []})
            continue
        frame = pd.read_csv(path)
        files.append({
            "path": relative, "boundary": split, "status": "available",
            "rows": len(frame), "columns": sorted(frame.columns.tolist()),
        })
        for index, row in frame.iterrows():
            records.append(normalize_record(row.to_dict(), split, int(index), registry))
    return records, files


def _counts(records: Iterable[dict[str, Any]], field: str, missing: str = "unknown") -> dict[str, int]:
    counter = Counter(str(record.get(field) if record.get(field) is not None else missing) for record in records)
    return dict(sorted(counter.items()))


def _duplicate_summary(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts = Counter(record[field] for record in records if record.get(field))
    groups = [count for count in counts.values() if count > 1]
    return {"groups": len(groups), "rows_in_groups": sum(groups), "duplicate_rows": sum(count - 1 for count in groups)}


def _near_duplicate_summary(records: list[dict[str, Any]]) -> dict[str, int | str]:
    fingerprints = [(index, int(record["_semantic_fingerprint"], 16), record["label"]) for index, record in enumerate(records)]
    parent = list(range(len(records)))

    def find(value: int) -> int:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    for offset, (left_index, left, label) in enumerate(fingerprints):
        for right_index, right, right_label in fingerprints[offset + 1:]:
            if label == right_label and _hamming(left, right) <= 3:
                left_root, right_root = find(left_index), find(right_index)
                if left_root != right_root:
                    parent[right_root] = left_root
    groups = Counter(find(index) for index in range(len(records)))
    duplicate_groups = [size for size in groups.values() if size > 1]
    return {
        "method": "64-bit tri-shingle SimHash, same label, Hamming distance <= 3",
        "groups": len(duplicate_groups), "rows_in_groups": sum(duplicate_groups),
        "near_duplicate_rows": sum(size - 1 for size in duplicate_groups),
    }


def _overlaps(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    by_split: dict[str, set[str]] = defaultdict(set)
    eligible: Counter[str] = Counter()
    for record in records:
        value = record.get(field)
        if value:
            by_split[record["split"]].add(str(value))
            eligible[record["split"]] += 1
    results = []
    splits = sorted(by_split)
    for index, left in enumerate(splits):
        for right in splits[index + 1:]:
            shared = by_split[left] & by_split[right]
            results.append({"left": left, "right": right, "shared": len(shared), "left_rows_with_value": eligible[left], "right_rows_with_value": eligible[right]})
    return results


def validate_corpus_boundaries(records: list[dict[str, Any]], strict: bool = True) -> dict[str, list[str]]:
    """Validate hard isolation rules and return non-fatal balance warnings."""
    errors: list[str] = []
    warnings: list[str] = []
    split_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        split_records[record["split"]].append(record)
        if record["split"] in TRAINING_SPLITS and record["external_evaluation_only"]:
            errors.append(f"external evaluation row entered {record['split']}")
        if record["split"] in TRAINING_SPLITS and record["language"] == "es":
            errors.append(f"Spanish row entered primary English boundary {record['split']}")
        source = record["source_name"].lower()
        if "spamassassin" in source and "spam" in source and record["label"] == 1:
            errors.append("generic SpamAssassin spam was labeled phishing")
        if record["split"] in TRAINING_SPLITS and ("phishtank" in source or "openphish" in source):
            errors.append("URL reputation data was used as an email-body label")
        if record["split"] in {"train", "validation", "test"} and not record["campaign_group"]:
            errors.append(f"missing campaign group in {record['split']}")
    isolated = {"train", "validation", "test", "external", "external_development", "external_final"}
    for field in ("content_hash", "normalized_content_hash", "campaign_group", "template_group"):
        for overlap in _overlaps([row for row in records if row["split"] in isolated], field):
            if overlap["shared"]:
                errors.append(f"{field} overlap between {overlap['left']} and {overlap['right']}: {overlap['shared']}")
    isolated_rows = [row for row in records if row["split"] in isolated]
    for offset, left in enumerate(isolated_rows):
        left_fingerprint = int(left["_semantic_fingerprint"], 16)
        for right in isolated_rows[offset + 1:]:
            if left["split"] == right["split"] or left["label"] != right["label"]:
                continue
            if _hamming(left_fingerprint, int(right["_semantic_fingerprint"], 16)) <= 3:
                errors.append(f"semantic near-duplicate overlap between {left['split']} and {right['split']}")
    for split, rows in sorted(split_records.items()):
        if not rows:
            continue
        synthetic_ratio = sum(row["is_synthetic"] is True for row in rows) / len(rows)
        if synthetic_ratio > 0.40:
            warnings.append(f"synthetic dominance in {split}: {synthetic_ratio:.1%}")
        source, count = Counter(row["source_name"] for row in rows).most_common(1)[0]
        if count / len(rows) > 0.50:
            warnings.append(f"source dominance in {split}: {source}={count / len(rows):.1%}")
    result = {"errors": sorted(set(errors)), "warnings": sorted(set(warnings))}
    if strict and result["errors"]:
        raise ValueError("Corpus boundary validation failed: " + "; ".join(result["errors"]))
    return result


def build_inventory(root: Path, boundaries: dict[str, str] | None = None) -> dict[str, Any]:
    records, files = load_boundary_records(root, boundaries)
    splits: dict[str, Any] = {}
    for split in sorted({record["split"] for record in records}):
        rows = [record for record in records if record["split"] == split]
        splits[split] = {
            "rows": len(rows), "labels": _counts(rows, "label"), "sources": _counts(rows, "source_name"),
            "class_ratio_phishing": round(sum(record["label"] == 1 for record in rows) / len(rows), 6),
            "source_ratios": {key: round(value / len(rows), 6) for key, value in _counts(rows, "source_name").items()},
        }
    missing = {
        field: sum(record.get(field) is None or record.get(field) == "" for record in records)
        for field in PROVENANCE_FIELDS
    }
    all_validation = validate_corpus_boundaries(records, strict=False)
    registry_path = root / "dataset_sources.json"
    registry_sources = []
    registered_names: set[str] = set()
    if registry_path.exists():
        raw_registry = json.loads(registry_path.read_text(encoding="utf-8"))["sources"]
        registry_sources = [
            {
                "id": source["id"], "name": source["name"], "status": source["status"],
                "role": source["role"], "license": source["license"],
                "assigned_project_label": source["assigned_project_label"],
            }
            for source in raw_registry
        ]
        registered_names = set(_registry_index(root)) | {source["name"] for source in raw_registry}
    lifecycle_files = []
    for lifecycle in ("raw", "interim", "processed", "external"):
        directory = root / "data" / lifecycle
        for path in sorted(candidate for candidate in directory.rglob("*") if candidate.is_file() and candidate.name != ".gitkeep"):
            lifecycle_files.append({
                "path": path.relative_to(root).as_posix(), "lifecycle": lifecycle,
                "format": path.suffix.lower().lstrip(".") or "unknown", "size_bytes": path.stat().st_size,
            })
    inventory = {
        "schema_version": 1,
        "deterministic": True,
        "configured_boundaries": files,
        "boundary_policy": "The v3 development pool uses grouped OOF folds and final fitting; no persistent train/validation/test row assignment exists. Diagnostics and external benchmarks are separately reported.",
        "fixed_split_counts": {"train": 0, "validation": 0, "test": 0},
        "source_registry": registry_sources,
        "unregistered_active_sources": sorted({record["source_name"] for record in records} - registered_names),
        "data_lifecycle_files": lifecycle_files,
        "total_rows": len(records),
        "rows_by_label": _counts(records, "label"),
        "rows_by_source": _counts(records, "source_name"),
        "rows_by_source_and_label": {
            source: _counts([record for record in records if record["source_name"] == source], "label")
            for source in sorted({record["source_name"] for record in records})
        },
        "rows_by_language": _counts(records, "language"),
        "rows_by_real_synthetic_status": {
            "real_or_curated": sum(row["is_synthetic"] is False for row in records),
            "synthetic": sum(row["is_synthetic"] is True for row in records),
            "unknown": sum(row["is_synthetic"] is None for row in records),
            "targeted_synthetic": sum(row["is_targeted_synthetic"] is True for row in records),
        },
        "rows_by_campaign_group": _counts(records, "campaign_group"),
        "unique_campaign_groups": len({row["campaign_group"] for row in records if row["campaign_group"]}),
        "rows_by_message_type": _counts(records, "message_type"),
        "rows_by_brand_family": _counts(records, "brand_family"),
        "rows_by_delivery_provider": _counts(records, "delivery_provider"),
        "duplicates": {"exact": _duplicate_summary(records, "content_hash"), "normalized": _duplicate_summary(records, "normalized_content_hash"), "semantic_near_duplicates": _near_duplicate_summary(records)},
        "missing_provenance_fields": missing,
        "missing_group_identifiers": {"campaign_group": sum(row["_original_campaign_missing"] for row in records), "template_group": sum(row["_original_template_missing"] for row in records)},
        "splits": splits,
        "overlap": {
            "exact_content": _overlaps(records, "content_hash"), "normalized_content": _overlaps(records, "normalized_content_hash"),
            "campaign": _overlaps(records, "campaign_group"), "template": _overlaps(records, "template_group"),
            "sender_domain": _overlaps(records, "sender_domain"), "subject_similarity": _overlaps(records, "_subject_key"),
        },
        "validation": all_validation,
        "privacy": "No message text, private recipient, or sender local-part is written to this inventory.",
    }
    return inventory


def inventory_markdown(inventory: dict[str, Any]) -> str:
    lines = ["# Corpus Inventory", "", "Deterministic audit of configured corpus boundaries. No message content is included.", "", f"- Total rows: {inventory['total_rows']}", f"- Labels: `{json.dumps(inventory['rows_by_label'], sort_keys=True)}`", f"- Languages: `{json.dumps(inventory['rows_by_language'], sort_keys=True)}`", f"- Unique campaign groups: {inventory['unique_campaign_groups']}", f"- Real/synthetic: `{json.dumps(inventory['rows_by_real_synthetic_status'], sort_keys=True)}`", "", "## Boundaries", "", "| Boundary | Rows | Phishing ratio |", "|---|---:|---:|"]
    for split, values in inventory["splits"].items():
        lines.append(f"| {split} | {values['rows']} | {values['class_ratio_phishing']:.1%} |")
    lines.extend(["", "## Source contribution", "", "| Source | Rows |", "|---|---:|"])
    for source, count in inventory["rows_by_source"].items():
        lines.append(f"| {source} | {count} |")
    lines.extend(["", "## Duplicate controls", "", f"- Exact duplicate rows: {inventory['duplicates']['exact']['duplicate_rows']}", f"- Normalized duplicate rows: {inventory['duplicates']['normalized']['duplicate_rows']}", f"- Semantic near-duplicate rows: {inventory['duplicates']['semantic_near_duplicates']['near_duplicate_rows']}", "", "## Validation", ""])
    if inventory["validation"]["errors"]:
        lines.extend(f"- ERROR: {item}" for item in inventory["validation"]["errors"])
    else:
        lines.append("- No hard boundary violation was found in the configured audit boundaries.")
    lines.extend(f"- WARNING: {item}" for item in inventory["validation"]["warnings"])
    lines.extend(["", "Missing provenance counts and all overlap matrices are preserved in the JSON report.", ""])
    return "\n".join(lines)


def write_inventory(root: Path, json_output: Path, markdown_output: Path, strict: bool = True) -> dict[str, Any]:
    inventory = build_inventory(root)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_output.write_text(inventory_markdown(inventory), encoding="utf-8")
    if strict and inventory["validation"]["errors"]:
        raise ValueError("Corpus inventory found hard leakage violations: " + "; ".join(inventory["validation"]["errors"]))
    return inventory
