"""Local-only orchestration for the restricted Phishing Pot staging pilot."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .corpus_inventory import ACTIVE_BOUNDARIES, load_boundary_records
from .controlled_acquisition import load_controlled_registry, validate_source_for_development
from .generalization import _hamming
from .phishing_pot_pilot import (
    PILOT_ID,
    PLANNED_COUNT,
    SOURCE_ID,
    _opaque_group,
    build_source_inventory,
    inventory_markdown,
    load_metadata_jsonl,
    preflight_markdown,
    selection_markdown,
    select_pilot_candidates,
    write_preflight_validation,
    write_safe_metadata_jsonl,
)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fingerprint_index(rows: Iterable[tuple[int, str]]) -> dict[tuple[int, int], list[tuple[int, int]]]:
    index: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for row_index, fingerprint in rows:
        try:
            value = int(fingerprint, 16)
        except (TypeError, ValueError):
            continue
        for chunk in range(4):
            index[(chunk, (value >> (chunk * 16)) & 0xFFFF)].append((row_index, value))
    return index


def _near_matches(value: int, index: dict[tuple[int, int], list[tuple[int, int]]]) -> set[int]:
    candidates: set[tuple[int, int]] = set()
    for chunk in range(4):
        candidates.update(index.get((chunk, (value >> (chunk * 16)) & 0xFFFF), ()))
    return {row_index for row_index, other in candidates if _hamming(value, other) <= 3}


def _staged_metadata(root: Path, current_metadata: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    staging = root / "data" / "staging"
    if not staging.exists():
        return rows
    for path in sorted(staging.glob("*/validation/*.jsonl")):
        if path.resolve() == current_metadata.resolve():
            continue
        if PILOT_ID in path.parts:
            # Idempotent reruns must not treat this pilot's prior selected
            # metadata as an independent staged boundary.
            continue
        try:
            rows.extend(load_metadata_jsonl(path))
        except (OSError, ValueError, json.JSONDecodeError):
            # An unsafe or non-metadata staging file is not silently trusted.
            raise ValueError(f"Could not safely load staged overlap metadata: {path}")
    return rows


def apply_overlap_validation(
    root: Path, records: list[dict[str, Any]], *, current_metadata: Path,
) -> dict[str, Any]:
    """Annotate exact, normalized, and SimHash overlap before selection."""
    boundary_rows, boundary_files = load_boundary_records(root, ACTIVE_BOUNDARIES)
    missing = [item["boundary"] for item in boundary_files if item["status"] != "available"]
    if missing:
        raise ValueError("Required corpus boundaries are unavailable: " + ", ".join(sorted(missing)))
    staged_rows = _staged_metadata(root, current_metadata)
    references: list[dict[str, Any]] = []
    for row in boundary_rows:
        references.append({
            "boundary": row["split"], "content_hash": row.get("content_hash"),
            "normalized_hash": row.get("normalized_content_hash"),
            "simhash": row.get("_semantic_fingerprint"),
        })
    for row in staged_rows:
        references.append({
            "boundary": "existing_staged_batch",
            "content_hash": row.get("content_hash") or row.get("sha256"),
            "normalized_hash": row.get("normalized_hash") or row.get("normalized_content_hash"),
            "simhash": row.get("simhash") or row.get("semantic_fingerprint"),
        })
    exact_index: dict[str, set[str]] = defaultdict(set)
    normalized_index: dict[str, set[str]] = defaultdict(set)
    for row in references:
        if row.get("content_hash"):
            exact_index[str(row["content_hash"])].add(str(row["boundary"]))
        if row.get("normalized_hash"):
            normalized_index[str(row["normalized_hash"])].add(str(row["boundary"]))
    semantic_index = _fingerprint_index(
        (index, str(row.get("simhash") or "")) for index, row in enumerate(references)
    )

    seen_exact: set[str] = set()
    seen_normalized: set[str] = set()
    internal_semantic = _fingerprint_index([])
    overlap_counts: Counter[str] = Counter()
    boundary_overlap_counts: Counter[str] = Counter()
    for row_index, row in enumerate(records):
        content_hash = str(row.get("content_hash") or "")
        normalized_hash = str(row.get("normalized_hash") or "")
        fingerprint_text = str(row.get("simhash") or "")
        categories: set[str] = set()
        boundaries: set[str] = set()
        if content_hash in exact_index:
            categories.add("exact")
            boundaries.update(exact_index[content_hash])
        if normalized_hash in normalized_index:
            categories.add("normalized")
            boundaries.update(normalized_index[normalized_hash])
        try:
            fingerprint = int(fingerprint_text, 16)
        except ValueError:
            fingerprint = -1
        if fingerprint >= 0:
            for match in _near_matches(fingerprint, semantic_index):
                categories.add("semantic_near_duplicate")
                boundaries.add(str(references[match]["boundary"]))
        internal_categories: set[str] = set()
        if content_hash and content_hash in seen_exact:
            internal_categories.add("exact_duplicate")
        if normalized_hash and normalized_hash in seen_normalized:
            internal_categories.add("normalized_duplicate")
        if fingerprint >= 0 and _near_matches(fingerprint, internal_semantic):
            internal_categories.add("semantic_near_duplicate")
        row["boundary_overlap"] = bool(categories)
        row["boundary_overlap_status"] = "overlap_detected" if categories else "compared_clear"
        row["boundary_overlap_categories"] = sorted(categories)
        row["boundary_overlap_boundaries"] = sorted(boundaries)
        row["internal_duplicate_status"] = "duplicate" if internal_categories else "clear"
        row["internal_duplicate_categories"] = sorted(internal_categories)
        overlap_counts.update(categories)
        overlap_counts.update(f"internal_{item}" for item in internal_categories)
        boundary_overlap_counts.update(boundaries)
        if content_hash:
            seen_exact.add(content_hash)
        if normalized_hash:
            seen_normalized.add(normalized_hash)
        if fingerprint >= 0:
            for chunk in range(4):
                internal_semantic[(chunk, (fingerprint >> (chunk * 16)) & 0xFFFF)].append((row_index, fingerprint))
    return {
        "boundary_files": boundary_files,
        "boundary_reference_count": len(boundary_rows),
        "existing_staged_reference_count": len(staged_rows),
        "overlap_counts": dict(sorted(overlap_counts.items())),
        "boundary_overlap_counts": dict(sorted(boundary_overlap_counts.items())),
    }


def _automatic_rejection_reasons(row: dict[str, Any]) -> list[str]:
    reasons = []
    if row.get("parse_safe") is not True or row.get("malformed") is True:
        reasons.append("reject_corrupt")
    if str(row.get("language") or "").lower() != "en":
        reasons.append("reject_non_english")
    if row.get("privacy_unresolved") is True:
        reasons.append("needs_privacy_redaction")
    if row.get("boundary_overlap") is True or row.get("internal_duplicate_status") == "duplicate":
        reasons.append("reject_duplicate")
    if row.get("phishing_intent") is not True:
        reasons.append("requires_taxonomy_review")
    return sorted(set(reasons))


def _candidate_source_map(repository_email_dir: Path) -> dict[str, Path]:
    root = repository_email_dir.resolve(strict=True)
    mapping: dict[str, Path] = {}
    for path in sorted(
        (item for item in repository_email_dir.rglob("*") if item.suffix.lower() == ".eml"),
        key=lambda item: item.as_posix().lower(),
    ):
        if path.is_symlink() or not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError("EML path escaped the configured source root")
        relative = resolved.relative_to(root)
        raw_hash = hashlib.sha256(resolved.read_bytes()).hexdigest()
        candidate_id = _opaque_group("candidate", relative.as_posix(), raw_hash)
        mapping[candidate_id] = resolved
    return mapping


def stage_raw_candidates(
    root: Path, repository_email_dir: Path, selected_ids: list[str],
) -> Path:
    if len(selected_ids) != PLANNED_COUNT or len(set(selected_ids)) != PLANNED_COUNT:
        raise ValueError(f"Pilot staging requires exactly {PLANNED_COUNT} unique candidate IDs")
    source_map = _candidate_source_map(repository_email_dir)
    missing = sorted(set(selected_ids) - set(source_map))
    if missing:
        raise ValueError(f"Selected candidates are absent from acquisition: {len(missing)}")
    pilot_dir = root / "data" / "staging" / PILOT_ID
    raw_dir = pilot_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    expected_names = {f"{candidate_id}.eml" for candidate_id in selected_ids}
    unexpected = sorted(path for path in raw_dir.glob("*.eml") if path.name not in expected_names)
    for path in unexpected:
        resolved = path.resolve(strict=True)
        if raw_dir.resolve(strict=True) not in resolved.parents or resolved.suffix.lower() != ".eml":
            raise ValueError("Pilot raw reconciliation escaped the staging raw directory")
        # These are reproducible staging copies, never source files.
        resolved.unlink()
    for candidate_id in selected_ids:
        source = source_map[candidate_id]
        destination = raw_dir / f"{candidate_id}.eml"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).hexdigest() != source_hash:
                raise ValueError(f"Staged checksum mismatch for {candidate_id}")
        else:
            shutil.copyfile(source, destination)
    if len(list(raw_dir.glob("*.eml"))) != PLANNED_COUNT:
        raise ValueError("Pilot raw staging does not contain exactly 22 EML files")
    return pilot_dir


def _write_reports(
    root: Path, records: list[dict[str, Any]], selection: dict[str, Any],
    overlap: dict[str, Any], output_dir: Path,
) -> dict[str, Any]:
    pilot = json.loads((root / "config/acquisition_batches" / f"{PILOT_ID}.json").read_text(encoding="utf-8"))
    acquisition = pilot["acquisition"]
    inventory = build_source_inventory(records, source_commit_sha=acquisition["commit_sha"])
    inventory.update({
        "repository_tree_eml_count": acquisition.get("repository_tree_eml_count", len(records)),
        "local_checkout_eml_count": acquisition.get("local_checkout_eml_count", len(records)),
        "local_checkout_unavailable_count": acquisition.get("local_checkout_unavailable_count", 0),
        "local_checkout_unavailable_reason": acquisition.get("local_checkout_unavailable_reason"),
    })
    _write_json(output_dir / "source_inventory.json", inventory)
    (output_dir / "source_inventory.md").write_text(inventory_markdown(inventory), encoding="utf-8")
    _write_json(output_dir / "candidate_selection.json", selection)
    (output_dir / "candidate_selection.md").write_text(selection_markdown(selection), encoding="utf-8")
    selected_by_id = {row["candidate_id"]: row for row in records}
    selected_rows = [selected_by_id[candidate_id] for candidate_id in selection["selected_candidate_ids"]]
    selected_privacy_flags = Counter(
        flag for row in selected_rows for flag in (row.get("privacy_flags") or [])
    )
    review_queue = {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "review_status": "awaiting_manual_review", "reviewed_count": 0,
        "allowed_classifications": [
            "phishing", "spam_not_phishing", "scam_not_phishing", "malware_not_phishing",
            "ambiguous", "reject_privacy", "reject_duplicate", "reject_non_english", "reject_corrupt",
        ],
        "samples": [
            {
                "candidate_id": candidate_id, "classification": None, "language": "en",
                "phishing_confirmed": None, "privacy_checks_passed": None,
                "license_checks_passed": None, "grouping_reviewed": None,
                "duplicate_checks_passed": True, "overlap_checks_passed": True,
                "campaign_group": selected_by_id[candidate_id]["campaign_group"],
                "template_group": selected_by_id[candidate_id]["template_group"],
                "manual_approved": None, "reviewer": None, "reviewed_at": None,
                "safe_notes": None,
            }
            for candidate_id in selection["selected_candidate_ids"]
        ],
    }
    _write_json(output_dir / "pilot_review_queue.json", review_queue)
    rejected = [
        {"candidate_id": row["candidate_id"], "reasons": reasons}
        for row in records if (reasons := _automatic_rejection_reasons(row))
    ]
    _write_json(output_dir / "rejected_rows.json", {
        "schema_version": 1, "pilot_id": PILOT_ID, "count": len(rejected),
        "rows": rejected, "privacy_note": "Only opaque candidate IDs and reason codes are included.",
    })
    duplicate_report = {
        "schema_version": 1, "pilot_id": PILOT_ID,
        "raw_file_exact_duplicate_count": inventory["raw_file_exact_duplicate_count"],
        "parsed_text_exact_duplicate_count": overlap["overlap_counts"].get("internal_exact_duplicate", 0),
        "normalized_duplicate_count": inventory["normalized_duplicate_count"],
        "semantic_near_duplicate_count": overlap["overlap_counts"].get("internal_semantic_near_duplicate", 0),
        **overlap, "selected_overlap_count": 0,
    }
    _write_json(output_dir / "duplicate_report.json", duplicate_report)
    tree_checksum = hashlib.sha256(
        "\n".join(sorted(str(row.get("sha256") or "") for row in records)).encode("ascii")
    ).hexdigest()
    _write_json(output_dir / "attribution_record.json", {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "source_title": "Phishing Pot", "creator": "rf-peixoto",
        "official_repository": acquisition["official_repository"],
        "source_commit_sha": acquisition["commit_sha"], "source_tree_sha": acquisition["tree_sha"],
        "acquisition_timestamp": acquisition["acquired_at_utc"],
        "acquisition_method": acquisition["method"], "license_reference": acquisition["license_reference"],
        "license": "CC BY-NC 4.0", "usage_mode": "noncommercial_research",
        "local_eml_inventory_sha256": tree_checksum, "raw_redistribution_allowed": False,
    })
    validation = {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "source_commit_sha": acquisition["commit_sha"], "inventory_count": len(records),
        "selected_count": selection["selected_count"], "awaiting_manual_review": selection["selected_count"],
        "ingestion_accepted_count": selection["selected_count"],
        "ingestion_rejected_count": len(rejected),
        "automatically_rejected_count": len(rejected),
        "eligible_unselected_reserve_count": len(records) - len(rejected) - selection["selected_count"],
        "selected_privacy_review_required_count": sum(
            bool(row.get("privacy_review_required")) for row in selected_rows
        ),
        "selected_privacy_flag_category_counts": dict(sorted(selected_privacy_flags.items())),
        "reviewed_count": 0,
        "promotion_eligible": False,
        "promotion_blockers": [
            "source_approval_incomplete", "development_use_disabled", "sample_review_incomplete",
            "privacy_approval_incomplete", "reviewer_decisions_missing",
        ],
    }
    _write_json(output_dir / "batch_validation.json", validation)
    markdown = "\n".join([
        "# Phishing Pot Pilot Batch Validation", "",
        f"- Inventory: {len(records)} EML metadata records",
        f"- Selected: {selection['selected_count']}",
        f"- Automatically rejected: {len(rejected)}",
        f"- Eligible unselected reserve: {len(records) - len(rejected) - selection['selected_count']}",
        f"- Awaiting manual review: {selection['selected_count']}",
        "- Reviewer decisions: 0", "- Promotion eligible: no", "",
        "No message bodies or sensitive values are included.", "",
    ])
    (output_dir / "batch_validation.md").write_text(markdown, encoding="utf-8")
    return validation


def run_pilot(
    root: Path, repository_email_dir: Path, metadata_path: Path, output_dir: Path,
    *, workers: int = 1, reuse_metadata: bool = False,
) -> dict[str, Any]:
    """Scan, compare, select, stage, and report without promotion or decisions."""
    preflight = write_preflight_validation(root, output_dir)
    if not preflight["passed"]:
        raise ValueError("Pilot preflight did not pass")
    if reuse_metadata:
        records = load_metadata_jsonl(metadata_path)
        local_eml_count = sum(
            1 for item in repository_email_dir.rglob("*")
            if item.suffix.lower() == ".eml" and not item.is_symlink()
        )
        if len(records) != local_eml_count:
            raise ValueError(
                "Reusable metadata is incomplete for the local checkout: "
                f"metadata={len(records)}, local_eml={local_eml_count}"
            )
        scan = {
            "scanned": len(records),
            "parse_safe": sum(row.get("parse_safe") is True for row in records),
            "unsafe": sum(row.get("parse_safe") is not True for row in records),
            "reused_atomic_metadata": True,
        }
    else:
        scan = write_safe_metadata_jsonl(repository_email_dir, metadata_path, workers=workers)
        records = load_metadata_jsonl(metadata_path)
    overlap = apply_overlap_validation(root, records, current_metadata=metadata_path)
    # Persist compared status so an interrupted run cannot select unchecked rows.
    with metadata_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in records:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    selection = select_pilot_candidates(records)
    stage_dir = stage_raw_candidates(root, repository_email_dir, selection["selected_candidate_ids"])
    validation_dir = stage_dir / "validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    selected = {row["candidate_id"]: row for row in records}
    with (validation_dir / "selected_metadata.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for candidate_id in selection["selected_candidate_ids"]:
            handle.write(json.dumps(selected[candidate_id], sort_keys=True) + "\n")
    _write_json(stage_dir / "manifest.json", {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "state": "awaiting_manual_review", "selected_count": PLANNED_COUNT,
        "selected_candidate_ids": selection["selected_candidate_ids"],
        "promotion_eligible": False, "development_allowed": False,
        "raw_redistribution_allowed": False,
    })
    validation = _write_reports(root, records, selection, overlap, output_dir)
    return {"scan": scan, "selection": selection, "validation": validation, "staging_directory": str(stage_dir)}


def write_blocked_promotion_preview(root: Path, review_queue_path: Path, output: Path) -> dict[str, Any]:
    """Dry-run the pilot gates and record the expected blocked result."""
    _, sources = load_controlled_registry(root / "config/dataset_source_registry.json")
    source = sources[SOURCE_ID]
    queue = json.loads(review_queue_path.read_text(encoding="utf-8"))
    samples = queue.get("samples") or []
    blockers: set[str] = set()
    try:
        validate_source_for_development(source)
    except PermissionError:
        if source.get("development_allowed") is not True:
            blockers.add("development_use_disabled")
        if source.get("approval_status") != "approved":
            blockers.add("source_approval_incomplete")
        if source.get("privacy_status") != "approved":
            blockers.add("source_privacy_review_incomplete")
        if source.get("ingestion_enabled") is not True:
            blockers.add("source_ingestion_disabled")
    if not samples or any(sample.get("classification") is None for sample in samples):
        blockers.add("manual_adjudication_incomplete")
    if any(sample.get("privacy_checks_passed") is not True for sample in samples):
        blockers.add("sample_privacy_review_incomplete")
    if any(sample.get("license_checks_passed") is not True for sample in samples):
        blockers.add("sample_license_review_incomplete")
    if any(sample.get("grouping_reviewed") is not True for sample in samples):
        blockers.add("campaign_template_review_incomplete")
    if any(sample.get("manual_approved") is not True for sample in samples):
        blockers.add("reviewer_approval_missing")
    report = {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "dry_run": True, "promotion_eligible": False,
        "result": "blocked_as_expected", "candidate_count": len(samples),
        "blockers": sorted(blockers), "files_copied": 0,
        "note": "The dry run did not promote, mutate, or expose any sample.",
    }
    if not blockers:
        raise RuntimeError("Pilot promotion preview unexpectedly found no blockers")
    _write_json(output, report)
    return report


def update_pilot_review(
    queue_path: Path, candidate_id: str, classification: str, reviewer: str, *,
    phishing_confirmed: bool = False, privacy_checks_passed: bool = False,
    license_checks_passed: bool = False, grouping_reviewed: bool = False,
    manual_approved: bool = False, safe_notes: str = "",
) -> dict[str, Any]:
    """Record one human decision without reading or copying message content."""
    from .controlled_acquisition import PILOT_REVIEW_CLASSIFICATIONS

    if classification not in PILOT_REVIEW_CLASSIFICATIONS:
        raise ValueError(f"Unsupported pilot classification: {classification}")
    if not reviewer.strip():
        raise ValueError("Reviewer is required")
    if len(safe_notes) > 500 or "@" in safe_notes or re.search(r"(?i)https?://|www\.", safe_notes):
        raise ValueError("safe_notes must not contain addresses, URLs, or more than 500 characters")
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    sample = next(
        (row for row in queue.get("samples", []) if row.get("candidate_id") == candidate_id),
        None,
    )
    if sample is None:
        raise KeyError(f"Pilot candidate not found: {candidate_id}")
    if classification == "phishing" and manual_approved and not all((
        phishing_confirmed, privacy_checks_passed, license_checks_passed, grouping_reviewed,
        sample.get("duplicate_checks_passed") is True,
        sample.get("overlap_checks_passed") is True,
    )):
        raise ValueError("Phishing approval requires completed content, privacy, license, grouping, duplicate, and overlap checks")
    sample.update({
        "classification": classification,
        "phishing_confirmed": phishing_confirmed,
        "privacy_checks_passed": privacy_checks_passed,
        "license_checks_passed": license_checks_passed,
        "grouping_reviewed": grouping_reviewed,
        "manual_approved": manual_approved,
        "reviewer": reviewer.strip(),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "safe_notes": safe_notes or None,
    })
    queue["reviewed_count"] = sum(row.get("classification") is not None for row in queue.get("samples", []))
    temporary = queue_path.with_name(f".{queue_path.name}.tmp")
    _write_json(temporary, queue)
    temporary.replace(queue_path)
    return sample
