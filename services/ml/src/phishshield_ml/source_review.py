"""Deterministic source-evidence audit and acquisition-batch readiness planning."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .controlled_acquisition import (
    LICENSE_STATUS_ENUM,
    PRIVACY_STATUS_ENUM,
    REGISTRY_FIELDS,
    STATUS_ENUM,
)


EVIDENCE_FIELDS = {
    "license_evidence_reference", "license_evidence_checked_at",
    "privacy_evidence_reference", "privacy_evidence_checked_at",
    "acquisition_evidence_reference", "reviewer", "review_notes", "unresolved_questions",
}
DOMINANT_SOURCE_ID = "zenodo_phishing_nlp_15235123"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _taxonomy(root: Path) -> dict[str, int]:
    payload = json.loads((root / "config/dataset_expansion_taxonomy.json").read_text(encoding="utf-8"))
    return {category["id"]: int(category["label"]) for category in payload["categories"]}


def audit_registry_payload(
    payload: dict[str, Any], taxonomy_labels: dict[str, int], legacy_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    global_issues: list[str] = []
    if set(payload.get("status_enums", [])) != STATUS_ENUM:
        global_issues.append("status_enums_conflict")
    controlled_ids: set[str] = set()
    sources = []
    legacy = {source["id"]: source for source in (legacy_payload or {}).get("sources", [])}
    for source in sorted(payload.get("sources", []), key=lambda item: item.get("source_id", "")):
        source_id = str(source.get("source_id") or "missing")
        issues: list[str] = []
        warnings: list[str] = []
        missing = sorted(REGISTRY_FIELDS - set(source))
        issues.extend(f"missing_field:{field}" for field in missing)
        if source_id in controlled_ids:
            issues.append("duplicate_source_id")
        controlled_ids.add(source_id)
        for field, allowed in {
            "license_status": LICENSE_STATUS_ENUM,
            "privacy_status": PRIVACY_STATUS_ENUM,
            "approval_status": STATUS_ENUM,
        }.items():
            if source.get(field) not in allowed:
                issues.append(f"invalid_status:{field}")
        if source.get("external_only"):
            if source.get("approval_status") != "external_only":
                issues.append("external_only_approval_conflict")
            if source.get("allowed_splits") != ["external"]:
                issues.append("external_only_split_conflict")
            if source.get("ingestion_enabled"):
                issues.append("external_only_ingestion_enabled")
        if source.get("ingestion_enabled"):
            if source.get("approval_status") != "approved":
                issues.append("enabled_without_source_approval")
            if source.get("license_status") != "approved":
                issues.append("enabled_without_license_approval")
            if source.get("privacy_status") != "approved":
                issues.append("enabled_without_privacy_approval")
            if not source.get("raw_storage_allowed"):
                issues.append("enabled_without_raw_storage_permission")
            if source.get("development_allowed") is False:
                issues.append("enabled_without_development_capability")
        if source.get("development_allowed") is True and source.get("approval_status") != "approved":
            issues.append("development_capability_without_approval")
        if source.get("redistribution_allowed") and source.get("license_status") != "approved":
            issues.append("redistribution_without_approved_license")
        if str(source.get("license", "")).lower().startswith("unknown") and source.get("license_status") != "pending":
            issues.append("unknown_license_not_pending")
        for field in EVIDENCE_FIELDS:
            if field not in source:
                issues.append(f"missing_evidence_field:{field}")
        if source.get("license_status") == "approved" and not source.get("license_evidence_reference"):
            issues.append("approved_license_missing_evidence")
        if source.get("privacy_status") == "approved" and not source.get("privacy_evidence_reference"):
            issues.append("approved_privacy_missing_evidence")
        if source.get("approval_status") == "approved" and not source.get("acquisition_evidence_reference"):
            issues.append("approved_source_missing_acquisition_evidence")
        labels = set(source.get("allowed_labels", []))
        for category in source.get("permitted_categories", []):
            if category not in taxonomy_labels:
                issues.append(f"unknown_permitted_category:{category}")
            elif taxonomy_labels[category] not in labels:
                issues.append(f"category_label_conflict:{category}")
        if labels and not source.get("permitted_categories") and not source.get("external_only"):
            warnings.append("labels_allowed_but_no_categories_permitted")
        if source.get("raw_storage_allowed") and not source.get("acquisition_evidence_reference"):
            issues.append("raw_storage_without_acquisition_evidence")
        legacy_source = legacy.get(source_id)
        if legacy_source:
            if legacy_source.get("official_page") != source.get("homepage"):
                issues.append("legacy_official_reference_conflict")
            legacy_external = legacy_source.get("role") == "external_validation_only"
            if legacy_external != bool(source.get("external_only")):
                issues.append("legacy_external_role_conflict")
            if legacy_source.get("status") == "blocked" and source.get("approval_status") == "approved":
                issues.append("legacy_blocked_but_controlled_approved")
        suitable_development = all([
            source.get("approval_status") == "approved", source.get("license_status") == "approved",
            source.get("privacy_status") == "approved", source.get("ingestion_enabled") is True,
            source.get("development_allowed", source.get("ingestion_enabled")) is True,
            source.get("external_only") is False, "development_pool" in source.get("allowed_splits", []),
            source.get("license_evidence_reference"), source.get("privacy_evidence_reference"),
            source.get("acquisition_evidence_reference"), not issues,
        ])
        external_evaluation_only = bool(source.get("external_only"))
        manual_review_required = bool(
            source.get("approval_status") in {"blocked", "pending"}
            or source.get("license_status") != "approved"
            or source.get("privacy_status") != "approved"
            or not source.get("license_evidence_reference")
            or not source.get("privacy_evidence_reference")
        )
        real_message_candidate = not source_id.startswith("phishphage-") and "url_feeds" not in source_id
        improves_diversity = (
            real_message_candidate and source_id != DOMINANT_SOURCE_ID
            and not external_evaluation_only and bool(labels)
            and "en" in source.get("allowed_languages", [])
        )
        missing_evidence = [
            name for name, field in (
                ("license", "license_evidence_reference"),
                ("privacy", "privacy_evidence_reference"),
                ("acquisition", "acquisition_evidence_reference"),
            ) if not source.get(field)
        ]
        sources.append({
            "source_id": source_id, "approval_status": source.get("approval_status"),
            "license_status": source.get("license_status"), "privacy_status": source.get("privacy_status"),
            "issues": sorted(set(issues)), "warnings": sorted(set(warnings)),
            "suitable_for_development": suitable_development,
            "external_evaluation_only": external_evaluation_only,
            "must_remain_blocked": source.get("approval_status") == "blocked",
            "manual_legal_or_privacy_review_required": manual_review_required,
            "duplicates_dominant_existing_source": source_id == DOMINANT_SOURCE_ID,
            "could_improve_source_diversity": improves_diversity,
            "missing_evidence": missing_evidence,
            "unresolved_questions": source.get("unresolved_questions", []),
        })
    missing_legacy = sorted(set(legacy) - controlled_ids)
    if missing_legacy:
        global_issues.append("legacy_sources_missing_from_controlled_registry:" + ",".join(missing_legacy))
    return {
        "schema_version": 1, "deterministic": True,
        "global_issues": sorted(global_issues), "sources": sources,
        "summary": {
            "total_sources": len(sources),
            "development_suitable": [row["source_id"] for row in sources if row["suitable_for_development"]],
            "external_only": [row["source_id"] for row in sources if row["external_evaluation_only"]],
            "blocked": [row["source_id"] for row in sources if row["must_remain_blocked"]],
            "manual_review_required": [row["source_id"] for row in sources if row["manual_legal_or_privacy_review_required"]],
            "potential_diversity_sources": [row["source_id"] for row in sources if row["could_improve_source_diversity"]],
            "sources_with_conflicts": [row["source_id"] for row in sources if row["issues"]],
            "sources_missing_evidence": [row["source_id"] for row in sources if row["missing_evidence"]],
            "duplicates_dominant_source": [row["source_id"] for row in sources if row["duplicates_dominant_existing_source"]],
        },
    }


def build_source_registry_audit(root: Path) -> dict[str, Any]:
    registry_path = root / "config/dataset_source_registry.json"
    legacy_path = root / "dataset_sources.json"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    legacy = json.loads(legacy_path.read_text(encoding="utf-8")) if legacy_path.exists() else None
    audit = audit_registry_payload(payload, _taxonomy(root), legacy)
    audit["inspected_paths"] = {
        "controlled_registry": "config/dataset_source_registry.json",
        "requested_manifest": {"path": "config/dataset_source_manifest.json", "exists": (root / "config/dataset_source_manifest.json").exists()},
        "example_manifest": {"path": "config/dataset_source_manifest.example.json", "exists": (root / "config/dataset_source_manifest.example.json").exists()},
        "requested_legacy_registry": {"path": "config/dataset_sources.json", "exists": (root / "config/dataset_sources.json").exists()},
        "actual_legacy_registry": {"path": "dataset_sources.json", "exists": legacy_path.exists()},
    }
    if not audit["inspected_paths"]["requested_manifest"]["exists"]:
        audit["global_issues"].append("requested_config_manifest_missing; example manifest inspected instead")
    if not audit["inspected_paths"]["requested_legacy_registry"]["exists"]:
        audit["global_issues"].append("requested_config_legacy_registry_missing; root legacy registry inspected instead")
    example_path = root / "config/dataset_source_manifest.example.json"
    if example_path.exists():
        example = json.loads(example_path.read_text(encoding="utf-8"))
        registry_equivalents = {
            "source_id", "display_name", "license_status", "privacy_status", "approval_status",
            "permitted_categories", "raw_storage_allowed", "required_redactions",
            "license_evidence_reference", "privacy_evidence_reference", "acquisition_evidence_reference",
        }
        missing_equivalents = sorted(registry_equivalents - set(example))
        audit["manifest_comparison"] = {
            "example_is_disabled": example.get("enabled") is False,
            "example_uses_legacy_schema": True,
            "missing_controlled_registry_equivalents": missing_equivalents,
        }
        if missing_equivalents:
            audit["global_issues"].append("example_manifest_schema_lags_controlled_registry")
    audit["global_issues"] = sorted(audit["global_issues"])
    return audit


def registry_audit_markdown(audit: dict[str, Any]) -> str:
    lines = ["# Source Registry Audit", "", "Deterministic internal-consistency and evidence audit. Public availability is not treated as approval.", "", "## Summary", ""]
    for key, value in audit["summary"].items():
        lines.append(f"- {key}: `{json.dumps(value, sort_keys=True)}`")
    lines.extend(["", "## Global issues", ""])
    lines.extend(f"- {issue}" for issue in audit["global_issues"] or ["none"])
    lines.extend(["", "## Sources", "", "| Source | Approval | License | Privacy | Development | External only | Issues |", "|---|---|---|---|---|---|---|"])
    for row in audit["sources"]:
        lines.append(f"| {row['source_id']} | {row['approval_status']} | {row['license_status']} | {row['privacy_status']} | {str(row['suitable_for_development']).lower()} | {str(row['external_evaluation_only']).lower()} | {', '.join(row['issues']) or 'none'} |")
    lines.append("")
    return "\n".join(lines)


def write_source_registry_audit(root: Path, json_output: Path, markdown_output: Path) -> dict[str, Any]:
    audit = build_source_registry_audit(root)
    _write_json(json_output, audit)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(registry_audit_markdown(audit), encoding="utf-8")
    return audit


def validate_batch_plan(plan: dict[str, Any], registry_payload: dict[str, Any], taxonomy_labels: dict[str, int]) -> dict[str, Any]:
    errors: list[str] = []
    blockers: list[str] = []
    sources = {source["source_id"]: source for source in registry_payload.get("sources", [])}
    approved_available_sources = {
        source_id for source_id, source in sources.items()
        if source.get("approval_status") == "approved"
        and source.get("license_status") == "approved"
        and source.get("privacy_status") == "approved"
        and source.get("ingestion_enabled") is True
        and source.get("development_allowed", source.get("ingestion_enabled")) is True
        and source.get("external_only") is False
        and "development_pool" in source.get("allowed_splits", [])
    }
    total = int(plan.get("planned_total", 0))
    target = plan.get("target_range", {})
    if not int(target.get("minimum", 0)) <= total <= int(target.get("maximum", 0)):
        errors.append("planned_total_outside_target_range")
    allocations = plan.get("allocations", [])
    allocation_total = sum(int(row.get("target_count", 0)) for row in allocations)
    if allocation_total != total:
        errors.append(f"allocation_total_mismatch:{allocation_total}!={total}")
    distributions = plan.get("source_distribution", [])
    distribution_total = sum(int(row.get("planned_count", 0)) for row in distributions)
    if distribution_total != total:
        errors.append(f"source_distribution_total_mismatch:{distribution_total}!={total}")
    if int(plan.get("synthetic_rows_planned", 0)) != 0 or any(row.get("is_synthetic") for row in distributions):
        errors.append("synthetic_allocation_prohibited")
    approved_families: set[str] = set()
    global_limit = float(plan.get("maximum_source_contribution_percent", 35))
    for distribution in distributions:
        count = int(distribution.get("planned_count", 0))
        ratio = 100 * count / total if total else 100
        limit = min(global_limit, float(distribution.get("configured_limit_percent", global_limit)))
        if ratio > limit:
            errors.append(f"source_contribution_limit_exceeded:{distribution['source_slot']}:{ratio:.2f}>{limit:.2f}")
        source_id = distribution.get("source_id")
        if not source_id:
            blockers.append(f"source_slot_unassigned:{distribution['source_slot']}")
            continue
        source = sources.get(source_id)
        if not source:
            errors.append(f"unregistered_source:{source_id}")
            continue
        if source.get("approval_status") == "blocked":
            blockers.append(f"blocked_source_scheduled:{source_id}")
        elif source.get("approval_status") != "approved":
            blockers.append(f"pending_source_scheduled:{source_id}")
        if source.get("development_allowed", source.get("ingestion_enabled", False)) is not True:
            blockers.append(f"development_capability_disabled:{source_id}")
        if source.get("external_only"):
            errors.append(f"external_only_source_scheduled_for_development:{source_id}")
        if source.get("license_status") not in {"approved", "verified_restricted_noncommercial"} or not source.get("license_evidence_reference"):
            blockers.append(f"license_evidence_not_ready:{source_id}")
        if source.get("privacy_status") != "approved" or not source.get("privacy_evidence_reference"):
            blockers.append(f"privacy_evidence_not_ready:{source_id}")
        if (
            source.get("approval_status") == "approved"
            and source.get("ingestion_enabled")
            and source.get("development_allowed", source.get("ingestion_enabled"))
        ):
            approved_families.add(str(distribution.get("independent_source_family") or source_id))
    minimum_sources = int(plan.get("minimum_approved_independent_sources", 2))
    if len(approved_available_sources) < minimum_sources:
        blockers.append(f"fewer_than_two_approved_independent_sources_available:{len(approved_available_sources)}<{minimum_sources}")
    if len(approved_families) < minimum_sources:
        blockers.append(f"fewer_than_two_approved_independent_sources_scheduled:{len(approved_families)}<{minimum_sources}")
    dominant = plan.get("dominant_existing_source", {})
    dominant_count = sum(int(row.get("planned_count", 0)) for row in distributions if row.get("source_id") == dominant.get("source_id"))
    dominant_ratio = 100 * dominant_count / total if total else 0
    if dominant_ratio > float(dominant.get("maximum_contribution_percent", 20)):
        errors.append(f"dominant_source_above_20_percent:{dominant_ratio:.2f}")
    template_limit = float(plan.get("maximum_template_contribution_percent", 5))
    for allocation in allocations:
        category = allocation.get("category")
        label = allocation.get("label")
        if category not in taxonomy_labels:
            errors.append(f"unknown_category:{category}")
        elif taxonomy_labels[category] != label:
            errors.append(f"taxonomy_label_mismatch:{category}")
        if int(allocation.get("minimum_campaign_groups", 0)) <= 0:
            errors.append(f"campaign_diversity_missing:{category}")
        templates = int(allocation.get("minimum_templates", 0))
        if templates <= 0:
            errors.append(f"template_diversity_missing:{category}")
        elif total and allocation.get("target_count", 0) / templates > total * template_limit / 100:
            errors.append(f"template_contribution_limit_not_supported:{category}")
        source_id = allocation.get("source_registry_id")
        if source_id:
            source = sources.get(source_id)
            if not source:
                errors.append(f"unregistered_allocation_source:{source_id}")
            else:
                if label not in source.get("allowed_labels", []):
                    errors.append(f"label_not_permitted:{source_id}:{label}")
                if category not in source.get("permitted_categories", []):
                    errors.append(f"category_not_permitted:{source_id}:{category}")
                if allocation.get("intended_use") not in source.get("allowed_splits", []):
                    blockers.append(f"split_not_currently_permitted:{source_id}:{allocation.get('intended_use')}")
        else:
            blockers.append(f"allocation_source_pending:{category}")
    conclusion = "invalid_batch_plan" if errors else "blocked_pending_source_approval" if blockers else "ready_for_acquisition"
    return {
        "schema_version": 1, "deterministic": True, "batch_id": plan.get("batch_id"),
        "conclusion": conclusion, "planned_total": total,
        "planned_source_distribution": {row["source_slot"]: row["planned_count"] for row in distributions},
        "planned_category_distribution": {row["category"]: row["target_count"] for row in allocations},
        "approved_independent_source_count": len(approved_available_sources),
        "scheduled_approved_independent_source_count": len(approved_families),
        "dominant_existing_source_percentage": round(dominant_ratio, 4),
        "errors": sorted(set(errors)), "approval_blockers": sorted(set(blockers)),
    }


def build_batch_readiness(root: Path, plan_path: Path | None = None) -> dict[str, Any]:
    plan = json.loads((plan_path or root / "config/acquisition_batches/batch_001.json").read_text(encoding="utf-8"))
    registry = json.loads((root / "config/dataset_source_registry.json").read_text(encoding="utf-8"))
    return validate_batch_plan(plan, registry, _taxonomy(root))


def readiness_markdown(report: dict[str, Any]) -> str:
    lines = ["# Batch 001 Readiness", "", f"Conclusion: **{report['conclusion']}**", "", f"Planned total: {report['planned_total']}", f"Approved independent sources available: {report['approved_independent_source_count']}", f"Approved independent sources scheduled: {report['scheduled_approved_independent_source_count']}", f"Dominant existing source contribution: {report['dominant_existing_source_percentage']:.2f}%", "", "## Errors", ""]
    lines.extend(f"- {item}" for item in report["errors"] or ["none"])
    lines.extend(["", "## Approval blockers", ""])
    lines.extend(f"- {item}" for item in report["approval_blockers"] or ["none"])
    lines.append("")
    return "\n".join(lines)


def write_batch_readiness(root: Path, json_output: Path, markdown_output: Path) -> dict[str, Any]:
    report = build_batch_readiness(root)
    _write_json(json_output, report)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(readiness_markdown(report), encoding="utf-8")
    return report


def write_source_review_packets(root: Path, output_directory: Path) -> list[Path]:
    registry = json.loads((root / "config/dataset_source_registry.json").read_text(encoding="utf-8"))
    plan = json.loads((root / "config/acquisition_batches/batch_001.json").read_text(encoding="utf-8"))
    planned = Counter()
    for row in plan["source_distribution"]:
        if row.get("source_id"):
            planned[row["source_id"]] += int(row["planned_count"])
    review_ids = {
        "cmu_enron_20150507", "apache_spamassassin_easy_ham",
        "apache_spamassassin_hard_ham", "spaphish_mendeley",
        "github_rf_peixoto_phishing_pot",
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    written = []
    for source in registry["sources"]:
        if source["source_id"] not in review_ids:
            continue
        claimed = source["license"]
        if source["license_status"] == "verified_restricted_noncommercial":
            claimed += " (VERIFIED, RESTRICTED TO NON-COMMERCIAL USE; NOT DEVELOPMENT-APPROVED)"
        elif source["license_status"] != "approved":
            claimed += " (UNVERIFIED OR INSUFFICIENT FOR APPROVAL)"
        if source["source_id"] == "github_rf_peixoto_phishing_pot":
            usefulness = "Could add independently collected real phishing campaigns from honeypots; it is never a legitimate-email source."
        elif "spamassassin" in source["source_id"] or "enron" in source["source_id"]:
            usefulness = "Could add independently sourced real legitimate English messages."
        else:
            usefulness = "Could add multilingual phishing evidence, but not to the primary English batch."
        lines = [
            f"# Source Review: {source['display_name']}", "",
            f"- Source ID: `{source['source_id']}`",
            f"- Why useful: {usefulness}",
            f"- Categories: `{json.dumps(source['permitted_categories'])}`",
            f"- Expected Batch 001 volume: {planned[source['source_id']]}",
            f"- Relationship to existing sources: independent of `{DOMINANT_SOURCE_ID}`",
            f"- Official reference: {source['homepage']}",
            f"- Claimed license: {claimed}",
            f"- Privacy concerns: {source['privacy_status']}; required redactions `{json.dumps(source['required_redactions'])}`",
            f"- Redistribution: {'allowed by current evidence' if source['redistribution_allowed'] else 'not approved'}",
            f"- Proposed storage policy: {'raw staging permitted after approval' if source['raw_storage_allowed'] else 'no raw storage until separately approved'}",
            f"- Permitted labels: `{json.dumps(source['allowed_labels'])}`",
            f"- Proposed status: `{source['approval_status']}` (unchanged)",
            f"- Unresolved questions: `{json.dumps(source['unresolved_questions'])}`", "",
            "## Exact evidence required before approval", "",
            "- Written license or rights analysis covering individual message content and the intended ML use.",
            "- Privacy review documenting personal-information handling, legal/public-interest basis, redactions, retention, and access controls.",
            "- Redistribution decision for raw text, normalized text, derived hashes/features, statistics, and repository inclusion.",
            "- Verified official acquisition method and checksum where available.",
            "- Named accountable human reviewer and dated approval decision.", "",
        ]
        if source["source_id"] == "github_rf_peixoto_phishing_pot":
            lines.extend([
                "## Phishing Pot-specific review", "",
                "- CC BY-NC 4.0 attribution: preserve creator, repository, license name/link, and modification notices in internal provenance and any permitted research output.",
                "- Non-commercial restriction: obtain a documented determination that every intended training, evaluation, deployment, collaboration, and publication use is non-commercial.",
                "- Third-party rights: determine whether repository licensing can authorize reuse of message bodies, branding, attachments, and other content authored by unrelated senders.",
                "- Recipient and URL privacy: inspect headers, visible bodies, HTML, URL query/path parameters, tracking tokens, and account identifiers for honeypot or third-party data.",
                "- Encoded content: decode MIME/Base64 locally in quarantine for inspection, never execute or render it, redact sensitive spans, and preserve only an authorized normalized derivative.",
                "- Attachments and malware: do not open, execute, extract, or promote attachment content; record metadata only unless a later isolated malware-handling protocol is approved.",
                "- Label review: reject generic spam, marketing, malware-only delivery, and non-phishing scams unless the message contains reviewed phishing or social-engineering behavior under the project taxonomy.",
                "- Language: accept only independently verified English samples for the primary model.",
                "- Grouping: assign campaign and template groups using normalized lure text, sender infrastructure, linked domains as inert strings, attachment metadata, and kit/brand patterns without contacting any destination.", "",
            ])
        path = output_directory / f"{source['source_id']}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        written.append(path)
    return written
