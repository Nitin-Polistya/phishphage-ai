"""Registry-gated staging, review, and promotion for future corpus batches.

The module performs local file processing only. It has no downloader and never
reads links, renders HTML, executes attachments, trains a model, or calls an API.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .corpus_inventory import ACTIVE_BOUNDARIES, normalize_record
from .dataset import canonicalize_template
from .generalization import _hamming, _simhash
from .preprocessing import normalize_email_text


STATUS_ENUM = {"approved", "blocked", "pending", "external_only"}
REVIEW_STATUS_ENUM = {"approve", "reject", "needs_revision", "external_only"}
REGISTRY_FIELDS = {
    "source_id", "display_name", "homepage", "dataset_reference", "license",
    "license_status", "privacy_status", "approval_status", "allowed_languages",
    "allowed_labels", "allowed_splits", "redistribution_allowed", "external_only",
    "ingestion_enabled", "approval_notes", "approved_by", "approved_date",
    "required_fields", "deduplication_policy", "campaign_policy", "supported_formats",
    "permitted_categories", "raw_storage_allowed", "required_redactions", "acquisition_method",
    "license_evidence_reference", "license_evidence_checked_at", "privacy_evidence_reference",
    "privacy_evidence_checked_at", "acquisition_evidence_reference", "reviewer", "review_notes",
    "unresolved_questions",
}
FORBIDDEN_PRIVACY_FIELDS = {
    "to", "cc", "bcc", "recipient", "recipient_email", "recipient_name",
    "sender_email", "raw_email", "attachment_content", "attachment_bytes",
}
BATCH_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _jsonl_write(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _jsonl_read(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_controlled_registry(path: str | Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if set(payload.get("status_enums", [])) != STATUS_ENUM:
        raise ValueError("Registry status_enums must be approved, blocked, pending, and external_only")
    records: dict[str, dict[str, Any]] = {}
    for source in payload.get("sources", []):
        missing = REGISTRY_FIELDS - set(source)
        if missing:
            raise ValueError(f"Registry source is missing fields: {sorted(missing)}")
        source_id = str(source["source_id"])
        if source_id in records:
            raise ValueError(f"Duplicate registry source_id: {source_id}")
        for field in ("license_status", "privacy_status", "approval_status"):
            if source[field] not in STATUS_ENUM:
                raise ValueError(f"Invalid {field} for {source_id}: {source[field]}")
        if str(source["license"]).strip().lower().startswith("unknown") and source["license_status"] != "pending":
            raise ValueError(f"Unknown license must remain pending: {source_id}")
        if source["ingestion_enabled"] and (
            source["approval_status"] != "approved"
            or source["license_status"] != "approved"
            or source["privacy_status"] != "approved"
            or source["external_only"]
        ):
            raise ValueError(f"Ingestion-enabled source is not fully approved: {source_id}")
        if source["ingestion_enabled"] and (not source["approved_by"] or not source["approved_date"]):
            raise ValueError(f"Ingestion-enabled source lacks approval attribution: {source_id}")
        if source["external_only"] and source["approval_status"] != "external_only":
            raise ValueError(f"External-only source has inconsistent approval status: {source_id}")
        records[source_id] = source
    return payload, records


def validate_source_for_ingestion(source: dict[str, Any], requested_split: str, input_format: str) -> None:
    source_id = source["source_id"]
    if source["external_only"] or source["approval_status"] == "external_only":
        raise PermissionError(f"Source {source_id} is external-only")
    if source["license_status"] != "approved":
        raise PermissionError(f"Source {source_id} license is not approved")
    if source["privacy_status"] != "approved":
        raise PermissionError(f"Source {source_id} privacy review is not approved")
    if source["approval_status"] != "approved":
        raise PermissionError(f"Source {source_id} approval is not approved")
    if not source["ingestion_enabled"]:
        raise PermissionError(f"Source {source_id} ingestion is disabled")
    if requested_split not in source["allowed_splits"]:
        raise PermissionError(f"Source {source_id} is not allowed in split {requested_split}")
    if input_format not in source["supported_formats"]:
        raise ValueError(f"Source {source_id} does not support {input_format}")


def batch_directory(root: Path, batch_id: str) -> Path:
    if not BATCH_ID_RE.fullmatch(batch_id):
        raise ValueError("batch_id must be 3-64 lowercase letters, digits, dots, underscores, or hyphens")
    return root / "data" / "staging" / batch_id


def initialize_batch(
    root: Path, batch_id: str, source_id: str, input_filename: str,
    requested_split: str = "development_pool", acquisition_date: str | None = None,
) -> Path:
    if Path(input_filename).name != input_filename or Path(input_filename).suffix.lower() not in {".csv", ".jsonl"}:
        raise ValueError("input_filename must be a plain .csv or .jsonl filename")
    directory = batch_directory(root, batch_id)
    if (directory / "manifest.json").exists():
        raise FileExistsError(f"Batch already exists: {batch_id}")
    for name in ("raw", "normalized", "validation", "reports"):
        (directory / name).mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1, "batch_id": batch_id, "source_id": source_id,
        "input_file": f"raw/{input_filename}", "requested_split": requested_split,
        "acquisition_date": acquisition_date, "created_at": _utc_now(),
        "state": "initialized",
    }
    _json_dump(directory / "manifest.json", manifest)
    return directory


def _read_input(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path).where(pd.notna, None).to_dict(orient="records")
    if path.suffix.lower() == ".jsonl":
        return _jsonl_read(path)
    raise ValueError(f"Unsupported input format: {path.suffix}")


def _taxonomy(root: Path) -> tuple[set[str], dict[str, int]]:
    payload = json.loads((root / "config" / "dataset_expansion_taxonomy.json").read_text(encoding="utf-8"))
    labels = {category["id"]: int(category["label"]) for category in payload["categories"]}
    return set(labels), labels


def _privacy_reasons(row: dict[str, Any]) -> list[str]:
    reasons = []
    for field in sorted(FORBIDDEN_PRIVACY_FIELDS):
        value = row.get(field)
        if value not in (None, "", [], {}):
            reasons.append(f"privacy_forbidden_field:{field}")
    source_record_id = str(row.get("source_record_id") or "")
    if EMAIL_RE.fullmatch(source_record_id):
        reasons.append("privacy_identifier_in:source_record_id")
    sender_domain = row.get("sender_domain")
    if sender_domain not in (None, "") and not DOMAIN_RE.fullmatch(str(sender_domain).strip()):
        reasons.append("privacy_sender_domain_not_organizational")
    return reasons


def _parse_boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    return None


def _reference_records(root: Path) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for split, relative in ACTIVE_BOUNDARIES.items():
        path = root / relative
        if not path.exists():
            continue
        frame = pd.read_csv(path).where(pd.notna, None)
        for index, row in frame.iterrows():
            references.append(normalize_record(row.to_dict(), split, int(index)))
    return references


def _overlap_reasons(candidate: dict[str, Any], references: list[dict[str, Any]]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    candidate_simhash = int(candidate["semantic_fingerprint"], 16)
    for reference in references:
        boundary = reference["split"]
        reason = None
        if candidate["content_hash"] == reference["content_hash"]:
            reason = "external_benchmark_overlap" if boundary.startswith("external") else "duplicate"
        elif candidate["normalized_content_hash"] == reference["normalized_content_hash"]:
            reason = "external_benchmark_normalized_overlap" if boundary.startswith("external") else "normalized_duplicate"
        elif candidate["campaign_group"] == reference.get("campaign_group") and reference.get("campaign_group"):
            reason = "external_campaign_overlap" if boundary.startswith("external") else "campaign_overlap"
        elif candidate["template_group"] == reference.get("template_group") and reference.get("template_group"):
            reason = "external_template_overlap" if boundary.startswith("external") else "template_overlap"
        elif candidate["label"] == reference["label"] and _hamming(candidate_simhash, int(reference["_semantic_fingerprint"], 16)) <= 3:
            reason = "external_near_duplicate" if boundary.startswith("external") else "near_duplicate"
        if reason:
            matches.append({"reason": reason, "boundary": boundary, "matched_sample_hash": reference["content_hash"][:20]})
    return matches


def _validation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Batch Validation", "", f"Batch: `{report['batch_id']}`", f"Source: `{report['source_id']}`",
        f"Input rows: {report['input_rows']}", f"Accepted for manual review: {report['accepted_rows']}",
        f"Rejected: {report['rejected_rows']}", f"Duplicate/overlap matches: {report['duplicate_matches']}", "",
        "No accepted row is promoted automatically. Every row remains in staging until manual review and confirmed promotion.", "",
    ]
    if report["rejection_reasons"]:
        lines.extend(["## Rejection reasons", ""])
        lines.extend(f"- {reason}: {count}" for reason, count in report["rejection_reasons"].items())
        lines.append("")
    return "\n".join(lines)


def ingest_batch(root: Path, batch_id: str, registry_path: Path | None = None) -> dict[str, Any]:
    directory = batch_directory(root, batch_id)
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Batch manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("batch_id") != batch_id:
        raise ValueError("Batch manifest ID does not match its directory")
    input_path = (directory / manifest["input_file"]).resolve()
    raw_root = (directory / "raw").resolve()
    if not input_path.is_relative_to(raw_root) or not input_path.is_file():
        raise ValueError("Batch input must be an existing file under the batch raw directory")
    _, registry = load_controlled_registry(registry_path or root / "config/dataset_source_registry.json")
    source_id = manifest["source_id"]
    if source_id not in registry:
        raise KeyError(f"Source is absent from the controlled registry: {source_id}")
    source = registry[source_id]
    validate_source_for_ingestion(source, manifest["requested_split"], input_path.suffix.lower().lstrip("."))
    categories, category_labels = _taxonomy(root)
    references = _reference_records(root)
    raw_rows = _read_input(input_path)
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    seen_normalized: set[str] = set()
    seen_simhashes: list[tuple[int, int]] = []

    for index, row in enumerate(raw_rows):
        source_record_id = str(row.get("source_record_id") or f"row-{index + 1}")
        audit_id = hashlib.sha256(f"{batch_id}:{source_record_id}".encode("utf-8")).hexdigest()[:20]
        reasons = _privacy_reasons(row)
        missing = [field for field in source["required_fields"] if row.get(field) in (None, "")]
        reasons.extend(f"missing_provenance:{field}" for field in missing)
        try:
            label = int(row.get("label"))
        except (TypeError, ValueError):
            label = -1
        language = str(row.get("language") or "").lower()
        category = str(row.get("message_type") or "")
        if label not in source["allowed_labels"]:
            reasons.append("unsupported_label")
        if language not in source["allowed_languages"]:
            reasons.append("unsupported_language")
        if category not in categories:
            reasons.append("missing_taxonomy")
        elif category_labels[category] != label:
            reasons.append("taxonomy_label_mismatch")
        if "spamassassin_spam" in source_id and label == 1:
            reasons.append("spam_relabelled_as_phishing")
        text = normalize_email_text(str(row.get("text") or ""))
        if not text:
            reasons.append("empty_text")
        is_synthetic = _parse_boolean(row.get("is_synthetic"))
        if is_synthetic is None:
            reasons.append("invalid_boolean:is_synthetic")
        if reasons:
            rejected.append({"sample_id": audit_id, "source_record_id": source_record_id, "reasons": sorted(set(reasons))})
            continue
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        normalized_hash = hashlib.sha256(canonicalize_template(text).encode("utf-8")).hexdigest()
        simhash = _simhash(text)
        candidate = {
            "sample_id": f"{source_id}:{audit_id}", "text": text, "label": label,
            "source_name": source_id, "source_record_id": source_record_id,
            "source_url_or_reference": source["dataset_reference"], "source_license": source["license"],
            "acquisition_date": manifest.get("acquisition_date"), "language": language,
            "is_synthetic": is_synthetic,
            "is_targeted_synthetic": bool(_parse_boolean(row.get("is_targeted_synthetic", False))),
            "campaign_group": str(row["campaign_group"]), "template_group": str(row["template_group"]),
            "message_type": category, "brand_family": row.get("brand_family"),
            "delivery_provider": row.get("delivery_provider"), "sender_domain": row.get("sender_domain"),
            "contains_urls": bool(row.get("contains_urls", URL_RE.search(text))),
            "contains_attachments": bool(row.get("contains_attachments", False)),
            "split": manifest["requested_split"], "external_evaluation_only": False,
            "content_hash": content_hash, "normalized_content_hash": normalized_hash,
            "semantic_fingerprint": f"{simhash:016x}", "notes": None,
        }
        overlap_matches = _overlap_reasons(candidate, references)
        if content_hash in seen_hashes:
            overlap_matches.append({"reason": "batch_duplicate", "boundary": "batch", "matched_sample_hash": content_hash[:20]})
        if normalized_hash in seen_normalized:
            overlap_matches.append({"reason": "batch_normalized_duplicate", "boundary": "batch", "matched_sample_hash": normalized_hash[:20]})
        if any(previous_label == label and _hamming(previous, simhash) <= 3 for previous_label, previous in seen_simhashes):
            overlap_matches.append({"reason": "batch_near_duplicate", "boundary": "batch", "matched_sample_hash": f"{simhash:016x}"})
        if overlap_matches:
            duplicates.append({"sample_id": candidate["sample_id"], "source_record_id": source_record_id, "matches": overlap_matches})
            rejected.append({"sample_id": candidate["sample_id"], "source_record_id": source_record_id, "reasons": sorted({match["reason"] for match in overlap_matches})})
            continue
        accepted.append(candidate)
        seen_hashes.add(content_hash)
        seen_normalized.add(normalized_hash)
        seen_simhashes.append((label, simhash))

    review_queue = [{
        "sample_id": row["sample_id"], "review_status": "needs_revision", "reviewer": None,
        "review_time": None, "review_notes": "awaiting_manual_review", "approved_label": None,
        "approved_category": None, "approved_campaign": None, "approved_template": None,
        "privacy_checked": False, "license_checked": False,
        "proposed_label": row["label"], "proposed_category": row["message_type"],
        "proposed_campaign": row["campaign_group"], "proposed_template": row["template_group"],
    } for row in accepted]
    _jsonl_write(directory / "normalized/normalized.jsonl", accepted)
    _jsonl_write(directory / "validation/review_queue.jsonl", review_queue)
    _json_dump(directory / "reports/rejected_rows.json", rejected)
    _json_dump(directory / "reports/duplicate_report.json", duplicates)
    reason_counts = Counter(reason for row in rejected for reason in row["reasons"])
    report = {
        "schema_version": 1, "batch_id": batch_id, "source_id": source_id,
        "input_rows": len(raw_rows), "accepted_rows": len(accepted), "rejected_rows": len(rejected),
        "duplicate_matches": len(duplicates), "rejection_reasons": dict(sorted(reason_counts.items())),
        "manual_review_rows": len(review_queue), "promotion_performed": False,
    }
    _json_dump(directory / "reports/batch_validation.json", report)
    (directory / "reports/batch_validation.md").write_text(_validation_markdown(report), encoding="utf-8")
    manifest["state"] = "awaiting_manual_review"
    manifest["validation_summary"] = {"accepted": len(accepted), "rejected": len(rejected)}
    _json_dump(manifest_path, manifest)
    return report


def update_review(
    root: Path, batch_id: str, sample_id: str, status: str, reviewer: str,
    notes: str = "", approved_label: int | None = None, approved_category: str | None = None,
    approved_campaign: str | None = None, approved_template: str | None = None,
    privacy_checked: bool = False, license_checked: bool = False,
) -> dict[str, Any]:
    if status not in REVIEW_STATUS_ENUM:
        raise ValueError(f"Unsupported review status: {status}")
    if not reviewer.strip():
        raise ValueError("Reviewer is required")
    queue_path = batch_directory(root, batch_id) / "validation/review_queue.jsonl"
    queue = _jsonl_read(queue_path)
    selected = next((row for row in queue if row["sample_id"] == sample_id), None)
    if selected is None:
        raise KeyError(f"Review sample not found: {sample_id}")
    if status == "approve":
        approved_label = selected["proposed_label"] if approved_label is None else approved_label
        approved_category = approved_category or selected["proposed_category"]
        approved_campaign = approved_campaign or selected["proposed_campaign"]
        approved_template = approved_template or selected["proposed_template"]
        if not privacy_checked or not license_checked:
            raise ValueError("Approval requires privacy_checked and license_checked")
        if None in (approved_label, approved_category, approved_campaign, approved_template):
            raise ValueError("Approval requires label, category, campaign, and template")
        _, taxonomy_labels = _taxonomy(root)
        if approved_category not in taxonomy_labels:
            raise ValueError(f"Approved category is absent from taxonomy: {approved_category}")
        if taxonomy_labels[approved_category] != int(approved_label):
            raise ValueError("Approved category and label do not agree")
        if not str(approved_campaign).strip() or not str(approved_template).strip():
            raise ValueError("Approved campaign and template cannot be empty")
    selected.update({
        "review_status": status, "reviewer": reviewer.strip(), "review_time": _utc_now(),
        "review_notes": notes, "approved_label": approved_label, "approved_category": approved_category,
        "approved_campaign": approved_campaign, "approved_template": approved_template,
        "privacy_checked": privacy_checked, "license_checked": license_checked,
    })
    _jsonl_write(queue_path, queue)
    return selected


def _promotion_markdown(preview: dict[str, Any]) -> str:
    lines = [
        "# Promotion Preview", "", f"Batch: `{preview['batch_id']}`", f"Mode: `{preview['mode']}`",
        f"Approved rows: {preview['approved_rows']}", f"Rejected rows: {preview['rejected_rows']}",
        f"Duplicate/overlap rows: {preview['duplicate_rows']}",
        f"Synthetic contribution: {preview['synthetic_percentage']:.2f}%",
        f"New campaigns: {preview['new_campaigns']}", "", "## Blockers", "",
    ]
    lines.extend(f"- {blocker}" for blocker in preview["blockers"] or ["none"])
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in preview["warnings"] or ["none"])
    lines.append("")
    return "\n".join(lines)


def promotion_preview(root: Path, batch_id: str, destination: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    directory = batch_directory(root, batch_id)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    _, registry = load_controlled_registry(root / "config/dataset_source_registry.json")
    source = registry.get(manifest["source_id"])
    if source is None:
        raise KeyError(f"Source is absent from the controlled registry: {manifest['source_id']}")
    input_format = Path(manifest["input_file"]).suffix.lower().lstrip(".")
    validate_source_for_ingestion(source, manifest["requested_split"], input_format)
    _, taxonomy_labels = _taxonomy(root)
    normalized = _jsonl_read(directory / "normalized/normalized.jsonl")
    queue = _jsonl_read(directory / "validation/review_queue.jsonl")
    rejected = json.loads((directory / "reports/rejected_rows.json").read_text(encoding="utf-8"))
    duplicates = json.loads((directory / "reports/duplicate_report.json").read_text(encoding="utf-8"))
    reviews = {row["sample_id"]: row for row in queue}
    approved: list[dict[str, Any]] = []
    blockers: list[str] = []
    for row in normalized:
        review = reviews.get(row["sample_id"])
        if not review or review["review_status"] != "approve":
            blockers.append(f"sample_not_approved:{row['sample_id']}")
            continue
        if not review["privacy_checked"] or not review["license_checked"]:
            blockers.append(f"review_checks_incomplete:{row['sample_id']}")
            continue
        promoted = dict(row)
        promoted.update({
            "label": int(review["approved_label"]), "message_type": review["approved_category"],
            "campaign_group": review["approved_campaign"], "template_group": review["approved_template"],
        })
        if promoted["label"] not in source["allowed_labels"]:
            blockers.append(f"approved_label_not_allowed:{row['sample_id']}")
            continue
        if taxonomy_labels.get(promoted["message_type"]) != promoted["label"]:
            blockers.append(f"approved_taxonomy_mismatch:{row['sample_id']}")
            continue
        approved.append(promoted)
    if rejected:
        blockers.append(f"ingestion_rejections_present:{len(rejected)}")
    if duplicates:
        blockers.append(f"duplicate_rows_present:{len(duplicates)}")
    destination_records: list[dict[str, Any]] = []
    if destination.exists():
        frame = pd.read_csv(destination).where(pd.notna, None)
        destination_records = [normalize_record(row.to_dict(), "development_pool", int(index)) for index, row in frame.iterrows()]
    external_records = []
    for split in ("external_development", "external_final"):
        path = root / ACTIVE_BOUNDARIES[split]
        if path.exists():
            frame = pd.read_csv(path).where(pd.notna, None)
            external_records.extend(normalize_record(row.to_dict(), split, int(index)) for index, row in frame.iterrows())
    recheck_duplicates = []
    for row in approved:
        matches = _overlap_reasons(row, destination_records + external_records)
        if matches:
            recheck_duplicates.append({"sample_id": row["sample_id"], "matches": matches})
            blockers.append(f"promotion_overlap:{row['sample_id']}")
    label_counts = Counter(str(row["label"]) for row in approved)
    source_counts = Counter(row["source_name"] for row in approved)
    campaign_counts = Counter(row["campaign_group"] for row in approved)
    taxonomy_counts = Counter(row["message_type"] for row in approved)
    synthetic_count = sum(row["is_synthetic"] is True for row in approved)
    existing_campaigns = {row.get("campaign_group") for row in destination_records if row.get("campaign_group")}
    warnings = []
    if approved and synthetic_count / len(approved) > 0.40:
        warnings.append("synthetic contribution exceeds 40%")
    if approved and source_counts.most_common(1)[0][1] / len(approved) > 0.50:
        warnings.append("one source exceeds 50% of the promotion batch")
    preview = {
        "schema_version": 1, "batch_id": batch_id, "mode": "dry_run",
        "approved_rows": len(approved), "rejected_rows": len(rejected),
        "duplicate_rows": len(duplicates) + len(recheck_duplicates),
        "class_balance": dict(sorted(label_counts.items())), "source_balance": dict(sorted(source_counts.items())),
        "campaign_balance": dict(sorted(campaign_counts.items())), "taxonomy_balance": dict(sorted(taxonomy_counts.items())),
        "synthetic_percentage": round(100 * synthetic_count / len(approved), 4) if approved else 0.0,
        "new_campaigns": len(set(campaign_counts) - existing_campaigns),
        "warnings": warnings, "blockers": sorted(set(blockers)),
        "promotion_performed": False, "destination": str(destination),
    }
    return preview, approved


def promote_batch(root: Path, batch_id: str, destination: Path, confirm: bool = False) -> dict[str, Any]:
    processed_root = (root / "data/processed").resolve()
    destination = destination.resolve()
    if not destination.is_relative_to(processed_root) or destination.suffix.lower() != ".csv":
        raise ValueError("Promotion destination must be a CSV under data/processed")
    preview, approved = promotion_preview(root, batch_id, destination)
    directory = batch_directory(root, batch_id)
    if not confirm:
        _json_dump(directory / "reports/promotion_preview.json", preview)
        (directory / "reports/promotion_preview.md").write_text(_promotion_markdown(preview), encoding="utf-8")
        return preview
    if preview["blockers"]:
        raise PermissionError("Promotion blocked: " + "; ".join(preview["blockers"]))
    if not approved:
        raise PermissionError("Promotion blocked: no approved rows")
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup = directory / "reports/promotion_backup.csv"
    before_hash = None
    if destination.exists():
        shutil.copy2(destination, backup)
        before_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
        current = pd.read_csv(destination).where(pd.notna, None)
    else:
        current = pd.DataFrame()
    promoted_rows = []
    for row in approved:
        promoted = dict(row)
        promoted.update({
            "source": row["source_name"],
            "provenance_type": "synthetic_controlled" if row["is_synthetic"] else "real_or_curated",
            "scenario": row["message_type"], "split_role": "development_pool",
        })
        promoted_rows.append(promoted)
    combined = pd.concat([current, pd.DataFrame(promoted_rows)], ignore_index=True, sort=False)
    temporary = destination.with_suffix(destination.suffix + ".promotion.tmp")
    combined.to_csv(temporary, index=False)
    temporary.replace(destination)
    after_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
    preview.update({
        "mode": "confirmed", "promotion_performed": True, "promoted_rows": len(approved),
        "destination_sha256_before": before_hash, "destination_sha256_after": after_hash,
        "rollback_backup": str(backup) if backup.exists() else None,
    })
    _json_dump(directory / "reports/promotion_preview.json", preview)
    (directory / "reports/promotion_preview.md").write_text(_promotion_markdown(preview), encoding="utf-8")
    _json_dump(directory / "reports/promotion_receipt.json", preview)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["state"] = "promoted"
    manifest["promotion_receipt"] = "reports/promotion_receipt.json"
    _json_dump(manifest_path, manifest)
    return preview
