"""Safe deterministic Batch 002 selection and weak-label dry-run workflow."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd

from .acquisition import parse_email_bytes, write_jsonl
from .dataset import canonicalize_template
from .phishing_pot_pilot import SOURCE_ID, _safe_identifier, load_metadata_jsonl
from .phishing_pot_run import _candidate_source_map
from .phishing_pot_triage import BLOCKING_PRIVACY_FLAGS, triage_candidate, triage_evidence
from .phishing_pot_weak_labels import (
    EMAIL_LIKE_PATTERN, SOURCE_COMMIT, WeakSamplingPolicy, build_derived_record,
    weak_label_eligibility,
)


BATCH_ID = "phishing_pot_batch_002"
SELECTION_SEED = "phishing-pot-batch-002-v1"
MAX_SELECTED = 500


@dataclass(frozen=True)
class Batch002Policy:
    seed: str = SELECTION_SEED
    maximum_selected: int = MAX_SELECTED
    maximum_per_campaign: int = 3
    maximum_per_template: int = 2
    maximum_recognized_brand_share: float = 0.15
    maximum_sender_infrastructure_share: float = 0.05
    preferred_maximum_family_share: float = 0.30
    maximum_source_share: float = 0.20
    source_weight: float = 0.35
    source_artifact_exclusion_enabled: bool = True


def _rank(seed: str, candidate_id: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{candidate_id}".encode()).hexdigest()


def _opaque(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.lower().strip().encode()).hexdigest()[:16]}"


def _family(row: Mapping[str, Any]) -> str:
    basis = set(str(item) for item in row.get("provisional_intent_basis") or [])
    theme = str(row.get("theme_group") or "other")
    if "theme:credential" in basis or theme == "credential":
        return "credential"
    if "theme:mfa_otp" in basis or theme == "mfa_otp":
        return "qr_or_mfa"
    if "theme:invoice_payment" in basis or theme == "invoice_payment":
        return "invoice_payment"
    if "theme:shipping" in basis or theme == "shipping":
        return "delivery"
    if "theme:account_security" in basis or theme == "account_security":
        return "account_security"
    return "generic_impersonation"


def _metadata_evidence_groups(row: Mapping[str, Any]) -> set[str]:
    basis = set(str(item) for item in row.get("provisional_intent_basis") or [])
    groups: set[str] = set()
    if "url_present" in basis:
        groups.add("destination")
    if "reply_to_mismatch" in basis:
        groups.add("identity_mismatch")
    if "urgency_language" in basis:
        groups.add("urgency")
    groups.update(item.removeprefix("theme:") for item in basis if item.startswith("theme:"))
    return groups


def batch002_exclusion_reasons(
    row: Mapping[str, Any], *, batch001_ids: set[str], unavailable_ids: set[str] | None = None,
) -> list[str]:
    """Return selection-stage exclusions using privacy-safe inventory metadata."""
    unavailable_ids = unavailable_ids or set()
    candidate_id = _safe_identifier(row.get("candidate_id"), "candidate_id")
    reasons: list[str] = []
    if candidate_id in batch001_ids:
        reasons.append("batch_001_boundary")
    if candidate_id in unavailable_ids:
        reasons.append("endpoint_security_unavailable")
    if row.get("parse_safe") is not True or row.get("malformed") is True:
        reasons.append("unsafe_or_malformed")
    if str(row.get("language") or "").lower() != "en" or float(row.get("language_confidence") or 0) < .80:
        reasons.append("non_english")
    if row.get("internal_duplicate_status") != "clear":
        reasons.append("exact_normalized_or_semantic_duplicate")
    if row.get("boundary_overlap") is True or row.get("boundary_overlap_status") != "compared_clear":
        reasons.append("protected_boundary_overlap")
    if not row.get("campaign_group") or not row.get("template_group") or not row.get("sender_infrastructure_group"):
        reasons.append("grouping_incomplete")
    if row.get("phishing_intent") is not True or len(_metadata_evidence_groups(row)) < 2:
        reasons.append("insufficient_phishing_evidence")
    attachment_only_metadata = int(row.get("attachment_count") or 0) > 0 and not any(
        group in _metadata_evidence_groups(row)
        for group in {"credential", "account_security", "invoice_payment", "shipping", "mfa_otp", "identity_mismatch"}
    )
    if attachment_only_metadata:
        reasons.append("attachment_only_without_social_engineering")
    return sorted(set(reasons))


def select_batch002_metadata(
    records: Iterable[Mapping[str, Any]], *, batch001_ids: set[str],
    unavailable_ids: set[str] | None = None, policy: Batch002Policy | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Select up to 500 metadata rows with deterministic diversity caps."""
    policy = policy or Batch002Policy()
    eligible: list[dict[str, Any]] = []
    exclusions: Counter[str] = Counter()
    for raw in records:
        row = dict(raw)
        reasons = batch002_exclusion_reasons(
            row, batch001_ids=batch001_ids, unavailable_ids=unavailable_ids,
        )
        if reasons:
            exclusions.update(reasons)
        else:
            eligible.append(row)

    dimension_fields = (
        "campaign_group", "template_group", "sender_infrastructure_group",
        "brand_group", "theme_group", "period_bucket",
    )
    frequencies = {
        field: Counter(str(row.get(field) or "unknown") for row in eligible)
        for field in dimension_fields
    }
    family_frequencies = Counter(_family(item) for item in eligible)

    def order(row: Mapping[str, Any]) -> tuple[bool, int, float, str]:
        rarity = sum(math.log1p(frequencies[field][str(row.get(field) or "unknown")]) for field in dimension_fields)
        rarity += math.log1p(family_frequencies[_family(row)])
        body_address = "address_in_decoded_content" in (row.get("privacy_flags") or [])
        evidence_strength = len(_metadata_evidence_groups(row)) + sum(
            bool(row.get(field)) for field in ("has_header_evidence", "has_url_evidence", "has_authentication_evidence")
        )
        return body_address, -evidence_strength, rarity, _rank(policy.seed, str(row["candidate_id"]))

    campaigns: Counter[str] = Counter()
    templates: Counter[str] = Counter()
    infrastructures: Counter[str] = Counter()
    brands: Counter[str] = Counter()
    families: Counter[str] = Counter()
    selected: list[dict[str, Any]] = []
    brand_cap = max(1, math.floor(policy.maximum_selected * policy.maximum_recognized_brand_share))
    infrastructure_cap = max(1, math.floor(policy.maximum_selected * policy.maximum_sender_infrastructure_share))
    family_cap = max(1, math.floor(policy.maximum_selected * policy.preferred_maximum_family_share))
    ordered = sorted(eligible, key=order)
    selected_ids: set[str] = set()
    selection_cap_reasons: dict[str, str] = {}

    def consider(row: dict[str, Any], *, enforce_family_preference: bool) -> None:
        if len(selected) >= policy.maximum_selected or str(row["candidate_id"]) in selected_ids:
            return
        campaign, template = str(row["campaign_group"]), str(row["template_group"])
        infrastructure = str(row["sender_infrastructure_group"])
        brand = str(row.get("brand_group") or "brand-unknown")
        family = _family(row)
        reason = None
        if campaigns[campaign] >= policy.maximum_per_campaign:
            reason = "campaign_selection_cap"
        elif templates[template] >= policy.maximum_per_template:
            reason = "template_selection_cap"
        elif infrastructures[infrastructure] >= infrastructure_cap:
            reason = "sender_infrastructure_selection_cap"
        elif brand != "brand-unknown" and brands[brand] >= brand_cap:
            reason = "recognized_brand_selection_cap"
        elif enforce_family_preference and families[family] >= family_cap:
            reason = "family_diversity_first_pass"
        if reason:
            selection_cap_reasons[str(row["candidate_id"])] = reason
            return
        item = dict(row)
        item["phishing_family"] = family
        item["mime_structure_group"] = _opaque("mime", "|".join(sorted(str(value) for value in row.get("mime_types") or [])))
        item["url_domain_group"] = str(row.get("sender_infrastructure_group"))
        item["selection_rank"] = len(selected) + 1
        selected.append(item)
        selected_ids.add(str(row["candidate_id"]))
        selection_cap_reasons.pop(str(row["candidate_id"]), None)
        campaigns[campaign] += 1
        templates[template] += 1
        infrastructures[infrastructure] += 1
        brands[brand] += 1
        families[family] += 1

    for row in ordered:
        consider(row, enforce_family_preference=True)
    if len(selected) < policy.maximum_selected:
        for row in ordered:
            consider(row, enforce_family_preference=False)
    exclusions.update(selection_cap_reasons.values())
    return selected, dict(sorted(exclusions.items()))


HONEYPOT_PATTERNS = {
    "explicit_honeypot_term": re.compile(r"(?i)\bhoneypot\b|\bspamtrap\b"),
    "collection_name_marker": re.compile(r"(?i)\bphishing[_ -]?pot\b|\brf-peixoto\b"),
    "honeypot_recipient_marker": re.compile(r"(?i)\b(?:phishing|phish|spam)[\w.+-]*@pot\b|\b[\w.+-]+@honeypot\b"),
}
COLLECTION_HEADER_PATTERN = re.compile(rb"(?im)^x-(?:phishing|honeypot|spamtrap|collection)[a-z0-9-]*\s*:")


def detect_source_artifacts(parsed: Mapping[str, Any], raw: bytes | None = None) -> list[str]:
    visible = "\n".join((str(parsed.get("subject") or ""), str(parsed.get("plain_body") or ""), str(parsed.get("sanitized_html_text") or "")))
    categories = [name for name, pattern in HONEYPOT_PATTERNS.items() if pattern.search(visible)]
    if raw is not None and COLLECTION_HEADER_PATTERN.search(raw[:256_000]):
        categories.append("collection_specific_header")
    return sorted(set(categories))


def leakage_scan_record(record: Mapping[str, Any]) -> list[str]:
    """Fail closed on sensitive values in a sanitized derived record."""
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True)
    findings: list[str] = []
    if EMAIL_LIKE_PATTERN.search(payload) or "@" in payload:
        findings.append("complete_email_address")
    if re.search(r"(?i)\b(?:https?|hxxps?)://|\bwww\.", payload):
        findings.append("complete_url")
    if re.search(r"(?i)\bmessage-id\s*:|\breceived\s*:", payload):
        findings.append("raw_transport_header")
    if any(key in record for key in ("attachment_filename", "attachment_filenames", "attachment_bytes", "raw_body", "raw_email")):
        findings.append("forbidden_raw_field")
    residual = (
        record.get("privacy_transformation_audit", {}).get("subject", {}).get("residual_sensitive_categories", [])
        + record.get("privacy_transformation_audit", {}).get("visible_text", {}).get("residual_sensitive_categories", [])
    )
    if residual:
        findings.append("redaction_residual")
    return sorted(set(findings))


def _safe_metadata_after_redaction(metadata: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(metadata)
    row["privacy_unresolved"] = False
    row["privacy_flags"] = sorted(set(str(item) for item in row.get("privacy_flags") or []) - BLOCKING_PRIVACY_FLAGS)
    return row


def derive_and_assess(
    raw: bytes, metadata: Mapping[str, Any], *, artifact_exclusion_enabled: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = parse_email_bytes(raw, source_id=SOURCE_ID, campaign_id="opaque")
    safe_metadata = _safe_metadata_after_redaction(metadata)
    evidence = triage_evidence(parsed, safe_metadata)
    record, redaction_audit = build_derived_record(parsed, safe_metadata, evidence)
    record["sender_infrastructure_group"] = str(metadata.get("sender_infrastructure_group"))
    record["phishing_family"] = _family(metadata)
    record["theme_group"] = str(metadata.get("theme_group") or "other")
    record["period_bucket"] = str(metadata.get("period_bucket") or "unknown")
    record["sender_domain_group"] = _opaque("sender", str(parsed.get("sender_domain") or "unknown"))
    record["url_domain_groups"] = [
        _opaque("url-domain", value) for value in record.pop("registrable_url_domains", [])
    ]
    triage = triage_candidate(safe_metadata, evidence)
    leakage = leakage_scan_record(record)
    if leakage:
        record["privacy_status"] = "privacy_blocked_irreducible"
        # A blocked row is retained only as a categorical audit stub. Never
        # persist the content that caused the fail-closed leakage result.
        record["text"] = "<PRIVACY_BLOCKED>"
        record["sanitized_subject"] = "<PRIVACY_BLOCKED>"
        record["sanitized_visible_text"] = "<PRIVACY_BLOCKED>"
        record["url_domain_groups"] = []
    artifacts = detect_source_artifacts(parsed, raw)
    eligible, blockers = weak_label_eligibility(record, safe_metadata, triage)
    if leakage:
        blockers.append("privacy_leakage_scan_failed")
    if artifacts and artifact_exclusion_enabled:
        blockers.append("source_collection_artifact")
    eligible = eligible and not leakage and not (artifacts and artifact_exclusion_enabled)
    audit = {
        "candidate_id": str(metadata["candidate_id"]),
        "privacy_status": record["privacy_status"],
        "leakage_findings": leakage,
        "source_artifact_categories": artifacts,
        "weak_label_eligible": eligible,
        "eligibility_blockers": sorted(set(blockers)),
        "independent_evidence_groups": triage.get("independent_evidence_groups", []),
        "provisional_outcome": triage.get("provisional_outcome"),
        "redaction_transformations": redaction_audit.get("transformation_counts", {}),
    }
    return record, audit


def select_assessed_candidates(
    assessed: Iterable[tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]],
    *, policy: Batch002Policy | None = None,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]], dict[str, int]]:
    """Form the final batch from strict static evidence under diversity caps."""
    policy = policy or Batch002Policy()
    candidates: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    exclusions: Counter[str] = Counter()
    for metadata, record, audit in assessed:
        if audit.get("provisional_outcome") != "high_confidence_phishing":
            exclusions["medium_or_insufficient_static_evidence"] += 1
            continue
        if audit.get("source_artifact_categories"):
            exclusions["source_collection_artifact"] += 1
            continue
        candidates.append((dict(metadata), dict(record), dict(audit)))
    ordered = sorted(
        candidates, key=lambda item: _rank(policy.seed + ":assessed", str(item[0]["candidate_id"])),
    )
    target = min(policy.maximum_selected, len(ordered))

    def select_with_caps(brand_cap: int, infrastructure_cap: int):
        chosen = []
        local_exclusions: Counter[str] = Counter()
        campaigns: Counter[str] = Counter()
        templates: Counter[str] = Counter()
        brands: Counter[str] = Counter()
        infrastructures: Counter[str] = Counter()
        for metadata, record, audit in ordered:
            if len(chosen) >= target:
                local_exclusions["maximum_selected_reached"] += 1
                continue
            campaign, template = str(record["campaign_group"]), str(record["template_group"])
            brand = str(record.get("brand_group") or f"brand-unknown-{record['sample_id']}")
            infrastructure = str(record.get("sender_infrastructure_group") or "infra-unknown")
            recognized = not brand.startswith("brand-unknown")
            if campaigns[campaign] >= policy.maximum_per_campaign:
                local_exclusions["campaign_final_cap"] += 1
            elif templates[template] >= policy.maximum_per_template:
                local_exclusions["template_final_cap"] += 1
            elif recognized and brands[brand] >= brand_cap:
                local_exclusions["brand_final_cap"] += 1
            elif infrastructures[infrastructure] >= infrastructure_cap:
                local_exclusions["sender_infrastructure_final_cap"] += 1
            else:
                chosen.append((metadata, record, audit))
                campaigns[campaign] += 1
                templates[template] += 1
                brands[brand] += 1
                infrastructures[infrastructure] += 1
        return chosen, local_exclusions

    brand_cap = max(1, math.floor(max(target, 1) * policy.maximum_recognized_brand_share))
    infrastructure_cap = max(1, math.floor(max(target, 1) * policy.maximum_sender_infrastructure_share))
    selected, cap_exclusions = select_with_caps(brand_cap, infrastructure_cap)
    for _ in range(8):
        next_brand = max(1, math.floor(max(len(selected), 1) * policy.maximum_recognized_brand_share))
        next_infrastructure = max(1, math.floor(max(len(selected), 1) * policy.maximum_sender_infrastructure_share))
        if (next_brand, next_infrastructure) == (brand_cap, infrastructure_cap):
            break
        brand_cap, infrastructure_cap = next_brand, next_infrastructure
        selected, cap_exclusions = select_with_caps(brand_cap, infrastructure_cap)
    exclusions.update(cap_exclusions)
    return selected, dict(sorted(exclusions.items()))


def sample_batch002(
    rows: Iterable[Mapping[str, Any]], *, existing_phishing_train_rows: int,
    policy: Batch002Policy | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    policy = policy or Batch002Policy()
    candidates = [dict(row) for row in rows]
    source_cap = math.floor(
        policy.maximum_source_share * existing_phishing_train_rows / (1 - policy.maximum_source_share)
    )
    target = min(len(candidates), source_cap)

    def select_with_caps(brand_cap: int, infrastructure_cap: int) -> tuple[list[dict[str, Any]], Counter[str]]:
        selected: list[dict[str, Any]] = []
        excluded: Counter[str] = Counter()
        campaigns: Counter[str] = Counter()
        templates: Counter[str] = Counter()
        brands: Counter[str] = Counter()
        infrastructures: Counter[str] = Counter()
        for row in sorted(candidates, key=lambda item: _rank(policy.seed + ":sample", str(item["sample_id"]))):
            if len(selected) >= target:
                excluded["source_share_cap"] += 1
                continue
            campaign, template = str(row["campaign_group"]), str(row["template_group"])
            brand = str(row.get("brand_group") or f"brand-unknown-{row['sample_id']}")
            infrastructure = str(row.get("sender_infrastructure_group") or "infra-unknown")
            recognized = not brand.startswith("brand-unknown")
            if campaigns[campaign] >= policy.maximum_per_campaign:
                excluded["campaign_cap"] += 1
            elif templates[template] >= policy.maximum_per_template:
                excluded["template_cap"] += 1
            elif recognized and brands[brand] >= brand_cap:
                excluded["brand_share_cap"] += 1
            elif infrastructures[infrastructure] >= infrastructure_cap:
                excluded["sender_infrastructure_cap"] += 1
            else:
                selected.append(row)
                campaigns[campaign] += 1
                templates[template] += 1
                brands[brand] += 1
                infrastructures[infrastructure] += 1
        return selected, excluded

    brand_cap = max(1, math.floor(max(target, 1) * policy.maximum_recognized_brand_share))
    infrastructure_cap = max(1, math.floor(max(target, 1) * policy.maximum_sender_infrastructure_share))
    selected, excluded = select_with_caps(brand_cap, infrastructure_cap)
    for _ in range(8):
        new_brand_cap = max(1, math.floor(max(len(selected), 1) * policy.maximum_recognized_brand_share))
        new_infra_cap = max(1, math.floor(max(len(selected), 1) * policy.maximum_sender_infrastructure_share))
        if (new_brand_cap, new_infra_cap) == (brand_cap, infrastructure_cap):
            break
        brand_cap, infrastructure_cap = new_brand_cap, new_infra_cap
        selected, excluded = select_with_caps(brand_cap, infrastructure_cap)
    return selected, dict(sorted(excluded.items()))


def analyze_shortcut_risk(rows: Iterable[Mapping[str, Any]], audits: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    records = list(rows)
    audit_rows = list(audits)
    dimensions: dict[str, Counter[str]] = {
        "sender_domain_groups": Counter(), "url_domain_groups": Counter(),
        "subject_prefix_hashes": Counter(), "html_boilerplate_hashes": Counter(),
        "footer_hashes": Counter(), "kit_wording_hashes": Counter(),
        "brand_groups": Counter(), "lexical_token_hashes": Counter(),
        "mime_structures": Counter(),
    }
    for row in records:
        dimensions["sender_domain_groups"][str(row.get("sender_domain_group") or "unknown")] += 1
        dimensions["url_domain_groups"].update(str(item) for item in row.get("url_domain_groups") or ["none"])
        subject = str(row.get("sanitized_subject") or "")
        text = str(row.get("sanitized_visible_text") or "")
        dimensions["subject_prefix_hashes"][_opaque("subject-prefix", subject[:32])] += 1
        if "text/html" in (row.get("mime_type_categories") or []):
            dimensions["html_boilerplate_hashes"][_opaque("html-template", canonicalize_template(text)[:500])] += 1
        dimensions["footer_hashes"][_opaque("footer", canonicalize_template(text[-240:]))] += 1
        dimensions["kit_wording_hashes"][_opaque("kit", canonicalize_template(text)[:500])] += 1
        dimensions["brand_groups"][str(row.get("brand_group") or "unknown")] += 1
        tokens = re.findall(r"[a-z]{4,}", text.lower())
        dimensions["lexical_token_hashes"].update(_opaque("token", token) for token in set(tokens))
        dimensions["mime_structures"][_opaque("mime", "|".join(row.get("mime_type_categories") or []))] += 1
    risks = []
    total = len(records)
    thresholds = {
        "sender_domain_groups": .10, "url_domain_groups": .10, "subject_prefix_hashes": .10,
        "html_boilerplate_hashes": .12, "footer_hashes": .12, "kit_wording_hashes": .12,
        "brand_groups": .15, "lexical_token_hashes": .50, "mime_structures": .60,
    }
    summaries = {}
    for name, counts in dimensions.items():
        top = counts.most_common(10)
        top_fraction = top[0][1] / total if top and total else 0.0
        summaries[name] = {
            "unique_groups": len(counts), "top_group_count": top[0][1] if top else 0,
            "top_group_fraction": round(top_fraction, 6),
            "top_group_hashes": [{"group": key, "count": count} for key, count in top],
        }
        if top_fraction > thresholds[name]:
            risks.append(f"repetitive_{name}")
    artifact_counts = Counter(
        item for audit in audit_rows for item in audit.get("source_artifact_categories") or []
    )
    if artifact_counts:
        risks.append("honeypot_or_collection_artifacts_detected")
    return {
        "schema_version": 1, "assessed_rows": total,
        "risk_categories": sorted(set(risks)),
        "dimension_summaries": summaries,
        "source_artifact_counts": dict(sorted(artifact_counts.items())),
        "artifact_exclusion_enabled": True,
        "interpretation": "Opaque repetition groups are shortcut-risk indicators, not evidence that frequent phishing behavior is benign.",
    }


def _existing_phishing_count(root: Path) -> int:
    frame = pd.read_csv(root / "data" / "processed" / "english_core.csv", usecols=["label"])
    return int(frame["label"].astype(str).str.lower().isin({"1", "phishing"}).sum())


def _verified_source_map(source_dir: Path, cache_path: Path) -> dict[str, Path]:
    """Reuse an ignored path cache, or verify all opaque IDs once and create it."""
    if cache_path.exists():
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        mapping = {candidate_id: source_dir / relative for candidate_id, relative in payload.items()}
        if len(mapping) == 8612 and all(path.is_file() for path in mapping.values()):
            return mapping
    mapping = _candidate_source_map(source_dir)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({
        candidate_id: path.relative_to(source_dir).as_posix()
        for candidate_id, path in sorted(mapping.items())
    }, sort_keys=True) + "\n", encoding="utf-8")
    return mapping


def run_batch002_dry_run(root: Path) -> dict[str, Any]:
    config = json.loads((root / "config" / "acquisition_batches" / f"{BATCH_ID}.json").read_text(encoding="utf-8"))
    policy = Batch002Policy()
    assessment_policy = Batch002Policy(maximum_selected=int(config.get("maximum_static_assessment_pool", 1500)))
    metadata_path = root / "data" / "external" / "phishing_pot" / "metadata" / "source_metadata.jsonl"
    records = load_metadata_jsonl(metadata_path)
    batch1_manifest = json.loads((root / "data" / "staging" / "phishing_pot_pilot_001" / "manifest.json").read_text(encoding="utf-8"))
    batch1_ids = set(str(item) for item in batch1_manifest["selected_candidate_ids"])
    assessment_metadata, selection_exclusions = select_batch002_metadata(
        records, batch001_ids=batch1_ids, policy=assessment_policy,
    )
    source_dir = root / "data" / "external" / "phishing_pot" / "repository" / "email"
    source_map = _verified_source_map(
        source_dir, root / "data" / "external" / "phishing_pot" / "metadata" / "candidate_path_map.json",
    )
    pre_map_assessment_count = len(assessment_metadata)
    assessment_metadata = [row for row in assessment_metadata if str(row["candidate_id"]) in source_map]
    missing_selected = pre_map_assessment_count - len(assessment_metadata)

    assessed: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for metadata in assessment_metadata:
        candidate_id = str(metadata["candidate_id"])
        record, audit = derive_and_assess(
            source_map[candidate_id].read_bytes(), metadata,
            artifact_exclusion_enabled=policy.source_artifact_exclusion_enabled,
        )
        assessed.append((metadata, record, audit))

    selected_assessed, final_selection_exclusions = select_assessed_candidates(assessed, policy=policy)
    selected_metadata = [metadata for metadata, _, _ in selected_assessed]
    derived = [record for _, record, _ in selected_assessed]
    audits = [audit for _, _, audit in selected_assessed]
    eligible = [record for _, record, audit in selected_assessed if audit["weak_label_eligible"]]

    existing_phishing = _existing_phishing_count(root)
    sampled, sampling_exclusions = sample_batch002(
        eligible, existing_phishing_train_rows=existing_phishing, policy=policy,
    )
    final_count = len(sampled)
    privacy_counts = Counter(item["privacy_status"] for item in audits)
    eligibility_exclusions = Counter(
        blocker for audit in audits for blocker in audit["eligibility_blockers"]
    )
    exclusion_totals = Counter(selection_exclusions)
    exclusion_totals.update(final_selection_exclusions)
    exclusion_totals.update(eligibility_exclusions)
    exclusion_totals.update(sampling_exclusions)
    exclusion_totals["endpoint_security_unavailable"] += int(config.get("acquisition", {}).get("local_checkout_unavailable_count", 2))
    shortcut = analyze_shortcut_risk(eligible, audits)
    artifact_excluded = int(final_selection_exclusions.get("source_collection_artifact", 0))
    if artifact_excluded:
        shortcut["source_artifact_counts"]["excluded_source_collection_artifact"] = artifact_excluded
        shortcut["risk_categories"] = sorted(set(shortcut["risk_categories"] + ["honeypot_or_collection_artifacts_detected_and_excluded"]))
    report_dir = root / "reports" / BATCH_ID
    interim_dir = root / "data" / "interim" / BATCH_ID
    report_dir.mkdir(parents=True, exist_ok=True)
    interim_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(interim_dir / "sanitized_derived_records.jsonl", derived)
    write_jsonl(interim_dir / "proposed_training_sample.jsonl", sampled)

    campaigns = {str(row["campaign_group"]) for row in selected_metadata}
    templates = {str(row["template_group"]) for row in selected_metadata}
    selected_brand_counts = Counter(str(row.get("brand_group") or "brand-unknown") for row in selected_metadata)
    selected_infra_counts = Counter(str(row.get("sender_infrastructure_group") or "infra-unknown") for row in selected_metadata)
    recognized_brand_max = max((count for brand, count in selected_brand_counts.items() if brand != "brand-unknown"), default=0)
    source_selection = {
        "schema_version": 1, "batch_id": BATCH_ID, "source_id": SOURCE_ID,
        "selection_seed": policy.seed, "inventory_rows": len(records),
        "static_assessment_pool": len(assessment_metadata),
        "endpoint_security_unavailable_files": 2, "batch_001_excluded": len(batch1_ids),
        "selected_count": len(selected_metadata), "safely_parsed_selected": len(audits),
        "independent_campaign_groups": len(campaigns), "independent_template_groups": len(templates),
        "maximum_recognized_brand_share_observed": recognized_brand_max / len(selected_metadata) if selected_metadata else 0.0,
        "maximum_sender_infrastructure_share_observed": max(selected_infra_counts.values(), default=0) / len(selected_metadata) if selected_metadata else 0.0,
        "family_distribution": dict(sorted(Counter(_family(row) for row in selected_metadata).items())),
        "selection_limits": {
            "campaign": policy.maximum_per_campaign, "template": policy.maximum_per_template,
            "recognized_brand_share": policy.maximum_recognized_brand_share,
            "sender_infrastructure_share": policy.maximum_sender_infrastructure_share,
        },
        "selected_candidate_ids": [row["candidate_id"] for row in selected_metadata],
        "missing_selected_source_files": missing_selected,
        "promotion_eligible": False, "training_executed": False,
        "acceptance_targets": {
            "selected_up_to_500": len(selected_metadata) <= 500,
            "privacy_sanitized_at_least_90_percent": privacy_counts["privacy_sanitized"] / len(audits) >= .90 if audits else False,
            "weak_label_eligible_preferably_150": len(eligible) >= 150,
            "campaign_groups_preferably_100": len(campaigns) >= 100,
            "template_groups_preferably_100": len(templates) >= 100,
            "sampled_rows_preferably_100_to_250": 100 <= final_count <= 250,
        },
    }
    privacy_report = {
        "schema_version": 1, "selected_count": len(audits),
        "privacy_status_counts": dict(sorted(privacy_counts.items())),
        "privacy_sanitized_rate": privacy_counts["privacy_sanitized"] / len(audits) if audits else 0.0,
        "leakage_scan_failure_count": sum(bool(item["leakage_findings"]) for item in audits),
        "source_artifact_counts": dict(sorted(Counter(value for item in audits for value in item["source_artifact_categories"]).items())),
        "records": audits, "raw_content_included": False,
    }
    eligibility_report = {
        "schema_version": 1, "assessed_rows": len(audits), "eligible_rows": len(eligible),
        "excluded_rows": len(audits) - len(eligible),
        "exclusion_reason_counts": dict(sorted(eligibility_exclusions.items())),
        "label": "phishing", "label_quality": "weak_source_provenance",
        "review_status": "not_manually_reviewed", "split_role": "train_only",
        "source_weight": policy.source_weight, "medium_confidence_auto_upgrade": False,
    }
    sampled_brand_counts = Counter(str(row.get("brand_group") or "brand-unknown") for row in sampled)
    sampled_infra_counts = Counter(str(row.get("sender_infrastructure_group") or "infra-unknown") for row in sampled)
    sampled_recognized_brand_max = max((count for brand, count in sampled_brand_counts.items() if not brand.startswith("brand-unknown")), default=0)
    sampling_report = {
        "schema_version": 1, "eligible_rows": len(eligible),
        "existing_phishing_training_rows": existing_phishing,
        "maximum_allowable_source_rows": math.floor(policy.maximum_source_share * existing_phishing / (1 - policy.maximum_source_share)),
        "proposed_final_sampled_rows": final_count,
        "estimated_source_share": final_count / (existing_phishing + final_count) if existing_phishing + final_count else 0.0,
        "sampling_exclusion_counts": sampling_exclusions,
        "campaign_groups": len({row["campaign_group"] for row in sampled}),
        "template_groups": len({row["template_group"] for row in sampled}),
        "maximum_recognized_brand_share_observed": sampled_recognized_brand_max / final_count if final_count else 0.0,
        "maximum_sender_infrastructure_share_observed": max(sampled_infra_counts.values(), default=0) / final_count if final_count else 0.0,
        "source_weight": policy.source_weight, "deterministic_seed": policy.seed,
        "active_dataset_modified": False,
    }
    exclusions_report = {
        "schema_version": 1, "selection_exclusion_counts": selection_exclusions,
        "post_parse_selection_exclusion_counts": final_selection_exclusions,
        "eligibility_exclusion_counts": dict(sorted(eligibility_exclusions.items())),
        "sampling_exclusion_counts": sampling_exclusions,
        "combined_gate_event_counts": dict(sorted(exclusion_totals.items())),
        "note": "Counts are gate events and may overlap for a single candidate.",
    }
    payloads = {
        "source_selection_summary.json": source_selection,
        "privacy_redaction_summary.json": privacy_report,
        "weak_label_eligibility_summary.json": eligibility_report,
        "campaign_balanced_sampling_summary.json": sampling_report,
        "source_shortcut_risk_summary.json": shortcut,
        "exclusion_reasons_summary.json": exclusions_report,
    }
    for name, payload in payloads.items():
        (report_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = [
        "# Phishing Pot Batch 002 source selection", "",
        "Dry run only; no source approval, promotion, active-dataset mutation, or training occurred.", "",
        f"- Inventory metadata rows: {len(records)}", f"- Selected: {len(selected_metadata)}",
        f"- Safely parsed: {len(audits)}", f"- Campaign groups: {len(campaigns)}",
        f"- Template groups: {len(templates)}", f"- Weak-label eligible: {len(eligible)}",
        f"- Proposed sampled rows: {final_count}", f"- Privacy sanitized: {privacy_counts['privacy_sanitized']}",
        "", "Quality targets are reported but never used to relax duplicate, overlap, evidence, privacy, or diversity gates.", "",
    ]
    (report_dir / "source_selection_summary.md").write_text("\n".join(markdown), encoding="utf-8")
    return {
        "selection": source_selection, "privacy": privacy_report,
        "eligibility": eligibility_report, "sampling": sampling_report,
        "shortcut": shortcut, "exclusions": exclusions_report,
    }
