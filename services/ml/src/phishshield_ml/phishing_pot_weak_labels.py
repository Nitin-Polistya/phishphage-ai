"""Controlled weak-label policy and privacy-safe Phishing Pot derivation.

This module is deliberately dry-run only. It never changes source approval,
review decisions, promotion state, models, or thresholds.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd

from .acquisition import URL_PATTERN, parse_email_bytes, write_jsonl
from .phishing_pot_pilot import PILOT_ID, SOURCE_ID, load_metadata_jsonl
from .phishing_pot_triage import EVIDENCE_GROUPS, triage_candidate, triage_evidence


LABEL_QUALITIES = (
    "gold_manual", "silver_multi_source", "weak_source_provenance",
    "synthetic", "unknown",
)
WEAK_LABEL_QUALITY = "weak_source_provenance"
WEAK_REVIEW_STATUS = "not_manually_reviewed"
WEAK_LABEL = "phishing"
SOURCE_COMMIT = "80685cbfe69a1f905707be92e144ba5b71f9ee37"

PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")
EMAIL_LIKE_PATTERN = re.compile(r"(?i)(?<![\w.+-])[a-z0-9][a-z0-9._%+-]*@[a-z0-9.-]+(?![\w.-])")
BROADER_EMAIL_PATTERN = re.compile(r"(?i)(?<!\S)[^\s@<>]+@[^\s@<>]+(?!\S)")
ANY_ATOM_EMAIL_PATTERN = re.compile(r"(?i)[^\s@<>\"]{1,128}@[^\s@<>\"]{1,255}")
PERSON_PATTERN = re.compile(r"(?im)\b(?:dear|hello|hi|attention)\s+([A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30}){0,2})\b")
ACCOUNT_PATTERN = re.compile(r"(?i)\b((?:subscription|account|customer|member|invoice|case|ticket|reference)\s+(?:id|number|no\.?|#)\s*[:=-]?\s*)([A-Z0-9][A-Z0-9._-]{4,})\b")
SECRET_PATTERN = re.compile(r"(?i)\b((?:password|passcode|otp|token|secret|api[_ -]?key|tracking[_ -]?id)\s*[:=]\s*)([^\s,;<>]{4,})")
LONG_TOKEN_PATTERN = re.compile(r"(?i)(?<![\w-])(?:[a-f0-9]{24,}|[a-z0-9_-]{32,})(?![\w-])")
RESIDUAL_URL_COMPONENT = re.compile(r"(?i)(?:https?|hxxps?)://\S*[?#]\S+")


@dataclass(frozen=True)
class WeakSamplingPolicy:
    maximum_source_share: float = 0.20
    maximum_per_campaign: int = 3
    maximum_per_template: int = 2
    maximum_per_recognized_brand_share: float = 0.20
    weak_sample_weight: float = 0.35
    deterministic_seed: str = "phishing-pot-weak-label-v1"
    campaign_aware_train_grouping_required: bool = True


def _registrable_domain(value: str) -> str:
    host = value.lower().strip(".")
    parts = [part for part in host.split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _url_token(match: re.Match[str], domains: set[str]) -> str:
    raw = match.group(0).rstrip(".,);]}")
    parseable = re.sub(r"(?i)^hxxps?://", "https://", raw)
    if parseable.lower().startswith("www."):
        parseable = "https://" + parseable
    try:
        host = urllib.parse.urlsplit(parseable).hostname or ""
    except ValueError:
        host = ""
    if host:
        domains.add(_registrable_domain(host))
    return "<URL_DOMAIN>"


def sanitize_visible_text(value: str) -> tuple[str, dict[str, Any], list[str]]:
    """Deterministically redact visible text and return only categorical audit data."""
    domains: set[str] = set()
    counts: Counter[str] = Counter()

    def replace(pattern: re.Pattern[str], text: str, token: str, category: str) -> str:
        def repl(_match: re.Match[str]) -> str:
            counts[category] += 1
            return token
        return pattern.sub(repl, text)

    def url_repl(match: re.Match[str]) -> str:
        counts["url"] += 1
        return _url_token(match, domains)

    sanitized = re.sub(r"(?im)^.*\b(?:received|message-id)\s*:.*$", "", str(value))
    sanitized = URL_PATTERN.sub(url_repl, sanitized)
    sanitized = re.sub(r"(?i)\b(?:https?|hxxps?)://\S+", "<URL_DOMAIN>", sanitized)
    sanitized = replace(EMAIL_LIKE_PATTERN, sanitized, "<EMAIL_ADDRESS>", "email_address")
    sanitized = replace(BROADER_EMAIL_PATTERN, sanitized, "<EMAIL_ADDRESS>", "email_address")
    sanitized = replace(ANY_ATOM_EMAIL_PATTERN, sanitized, "<EMAIL_ADDRESS>", "email_address")
    sanitized = replace(PHONE_PATTERN, sanitized, "<PHONE_NUMBER>", "phone_number")
    sanitized = PERSON_PATTERN.sub(
        lambda match: f"{match.group(0)[:match.group(0).find(match.group(1))]}<PERSON_NAME>",
        sanitized,
    )
    if PERSON_PATTERN.search(str(value)):
        counts["person_name"] += len(PERSON_PATTERN.findall(str(value)))
    account_matches = len(ACCOUNT_PATTERN.findall(sanitized))
    sanitized = ACCOUNT_PATTERN.sub(lambda m: f"{m.group(1)}<ACCOUNT_ID>", sanitized)
    counts["account_id"] += account_matches
    sanitized = SECRET_PATTERN.sub(lambda m: f"{m.group(1)}<ACCOUNT_ID>", sanitized)
    counts["secret_or_credential"] += len(SECRET_PATTERN.findall(str(value)))
    sanitized = replace(LONG_TOKEN_PATTERN, sanitized, "<ACCOUNT_ID>", "long_token")
    sanitized = re.sub(r"[ \t]+", " ", sanitized)
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized).strip()
    residual = []
    if EMAIL_LIKE_PATTERN.search(sanitized) or "@" in sanitized:
        residual.append("email_address")
    if RESIDUAL_URL_COMPONENT.search(sanitized):
        residual.append("url_query_or_fragment")
    if SECRET_PATTERN.search(sanitized) or LONG_TOKEN_PATTERN.search(sanitized):
        residual.append("token_or_credential")
    audit = {
        "transformations": dict(sorted(counts.items())),
        "url_domain_count": len(domains),
        "residual_sensitive_categories": sorted(set(residual)),
    }
    return sanitized, audit, sorted(domains)


def _attachment_category(content_type: str) -> str:
    value = content_type.lower()
    if value == "application/pdf":
        return "<ATTACHMENT_PDF>"
    if value in {"application/zip", "application/x-rar-compressed", "application/x-7z-compressed"}:
        return "<ATTACHMENT_ARCHIVE>"
    return "<ATTACHMENT_OTHER>"


def _size_bucket(size: int) -> str:
    if size == 0:
        return "none"
    if size < 100_000:
        return "small"
    if size < 1_000_000:
        return "medium"
    return "large"


def build_derived_record(
    parsed: Mapping[str, Any], metadata: Mapping[str, Any], evidence: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a sanitized train-only preview record without attachment bytes/names."""
    subject, subject_audit, subject_domains = sanitize_visible_text(str(parsed.get("subject") or ""))
    visible = str(parsed.get("plain_body") or parsed.get("sanitized_html_text") or "")
    text, text_audit, text_domains = sanitize_visible_text(visible)
    residual = sorted(set(subject_audit["residual_sensitive_categories"] + text_audit["residual_sensitive_categories"]))
    if metadata.get("privacy_unresolved"):
        residual.append("metadata_privacy_unresolved")
    privacy_status = "privacy_blocked_irreducible" if residual else "privacy_sanitized"
    attachments = list(parsed.get("attachments") or [])
    auth_blob = " ".join(
        str(item) for values in (parsed.get("authentication_headers") or {}).values()
        for item in (values if isinstance(values, list) else [values])
    )
    auth_summary = {
        mechanism: (
            "fail" if re.search(rf"(?i)\b{mechanism}\s*=\s*(?:fail|softfail|permerror|temperror)\b", auth_blob)
            else "pass" if re.search(rf"(?i)\b{mechanism}\s*=\s*pass\b", auth_blob)
            else "unavailable"
        ) for mechanism in ("spf", "dkim", "dmarc")
    }
    sender = str(parsed.get("sender_domain") or "")
    reply = str(parsed.get("reply_to_domain") or "")
    record = {
        "sample_id": str(metadata.get("candidate_id")),
        "text": f"Subject: {subject}\n\n{text}".strip(),
        "sanitized_subject": subject,
        "sanitized_visible_text": text,
        "registrable_url_domains": sorted(set(subject_domains + text_domains)),
        "domain_relationships": {
            "sender_present": bool(sender), "reply_to_present": bool(reply),
            "sender_reply_to_aligned": bool(sender and reply and _registrable_domain(sender) == _registrable_domain(reply)),
        },
        "authentication_summary": auth_summary,
        "mime_type_categories": sorted(set(str(item) for item in parsed.get("mime_types") or [])),
        "attachment_tokens": sorted(_attachment_category(str(item.get("content_type") or "")) for item in attachments),
        "attachment_count": len(attachments),
        "attachment_size_bucket": _size_bucket(sum(int(item.get("bytes") or 0) for item in attachments)),
        "label": WEAK_LABEL,
        "label_quality": WEAK_LABEL_QUALITY,
        "source_id": SOURCE_ID,
        "source_commit": SOURCE_COMMIT,
        "source_weight": WeakSamplingPolicy().weak_sample_weight,
        "campaign_group": str(metadata.get("campaign_group")),
        "template_group": str(metadata.get("template_group")),
        "brand_group": (
            f"brand-unknown-{hashlib.sha256(str(metadata.get('candidate_id')).encode()).hexdigest()[:12]}"
            if str(metadata.get("brand_group") or "brand-unknown") == "brand-unknown"
            else str(metadata.get("brand_group"))
        ),
        "automated_evidence": sorted(
            key for key, value in evidence.items()
            if value is True and key not in {"attachment_present"}
        ),
        "privacy_status": privacy_status,
        "review_status": WEAK_REVIEW_STATUS,
        "split_role": "train_only",
        "privacy_transformation_audit": {
            "subject": subject_audit, "visible_text": text_audit,
            "attachment_filenames_removed": len(attachments),
            "received_chain_retained": False, "raw_message_id_retained": False,
        },
    }
    audit = {
        "candidate_id": record["sample_id"], "privacy_status": privacy_status,
        "transformation_counts": {
            key: subject_audit["transformations"].get(key, 0) + text_audit["transformations"].get(key, 0)
            for key in sorted(set(subject_audit["transformations"]) | set(text_audit["transformations"]))
        },
        "residual_sensitive_categories": sorted(set(residual)),
        "attachment_filenames_removed": len(attachments),
    }
    return record, audit


def weak_label_eligibility(
    record: Mapping[str, Any], metadata: Mapping[str, Any], triage: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if str(metadata.get("language")) != "en" or float(metadata.get("language_confidence") or 0) < 0.80:
        blockers.append("english_gate_failed")
    if metadata.get("parse_safe") is not True or metadata.get("malformed") is True:
        blockers.append("unsafe_or_corrupt_parse")
    if record.get("privacy_status") != "privacy_sanitized":
        blockers.append("privacy_not_sanitized")
    if metadata.get("internal_duplicate_status") != "clear" or metadata.get("boundary_overlap") is True:
        blockers.append("duplicate_or_external_boundary_conflict")
    if len(triage.get("independent_evidence_groups") or []) < 2:
        blockers.append("insufficient_independent_evidence")
    if "attachment_only" in (triage.get("supporting_evidence_categories") or []):
        blockers.append("attachment_only")
    if "spam_only" in (triage.get("supporting_evidence_categories") or []):
        blockers.append("generic_spam_only")
    if triage.get("provisional_outcome") != "high_confidence_phishing":
        blockers.append("medium_or_non_high_triage")
    if not record.get("source_commit") or record.get("source_id") != SOURCE_ID:
        blockers.append("source_provenance_missing")
    if record.get("label_quality") != WEAK_LABEL_QUALITY:
        blockers.append("wrong_label_quality")
    return not blockers, sorted(set(blockers))


def _rank(seed: str, sample_id: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{sample_id}".encode()).hexdigest()


def sample_campaign_balanced(
    rows: Iterable[Mapping[str, Any]], *, existing_phishing_train_rows: int,
    policy: WeakSamplingPolicy | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    policy = policy or WeakSamplingPolicy()
    candidates = sorted((dict(row) for row in rows), key=lambda row: _rank(policy.deterministic_seed, str(row["sample_id"])))
    maximum_source_rows = math.floor(
        policy.maximum_source_share * existing_phishing_train_rows / (1 - policy.maximum_source_share)
    ) if policy.maximum_source_share < 1 else len(candidates)
    target_capacity = min(len(candidates), maximum_source_rows)
    per_brand_cap = max(1, math.floor(max(target_capacity, 1) * policy.maximum_per_recognized_brand_share))
    campaign_counts: Counter[str] = Counter()
    template_counts: Counter[str] = Counter()
    brand_counts: Counter[str] = Counter()
    excluded: Counter[str] = Counter()
    selected: list[dict[str, Any]] = []
    for row in candidates:
        if len(selected) >= target_capacity:
            excluded["source_share_cap"] += 1
            continue
        campaign = str(row["campaign_group"])
        template = str(row["template_group"])
        brand = str(row.get("brand_group") or f"unknown-{row['sample_id']}")
        recognized = not brand.startswith("brand-unknown") and not brand.startswith("unknown-")
        if campaign_counts[campaign] >= policy.maximum_per_campaign:
            excluded["campaign_cap"] += 1
            continue
        if template_counts[template] >= policy.maximum_per_template:
            excluded["template_cap"] += 1
            continue
        if recognized and brand_counts[brand] >= per_brand_cap:
            excluded["brand_share_cap"] += 1
            continue
        selected.append(row)
        campaign_counts[campaign] += 1
        template_counts[template] += 1
        brand_counts[brand] += 1
    return selected, dict(sorted(excluded.items()))


def _existing_phishing_count(root: Path) -> int:
    path = root / "data" / "processed" / "english_core.csv"
    if not path.exists():
        return 0
    frame = pd.read_csv(path, usecols=["label"])
    return int(frame["label"].astype(str).str.lower().isin({"1", "phishing"}).sum())


def run_policy_dry_run(root: Path) -> dict[str, Any]:
    stage = root / "data" / "staging" / PILOT_ID
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    metadata_rows = load_metadata_jsonl(stage / "validation" / "selected_metadata.jsonl")
    metadata_by_id = {str(row["candidate_id"]): row for row in metadata_rows}
    derived: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    eligibility_rows: list[dict[str, Any]] = []
    gate_exclusions: Counter[str] = Counter()
    for candidate_id in manifest["selected_candidate_ids"]:
        metadata = metadata_by_id[str(candidate_id)]
        parsed = parse_email_bytes((stage / "raw" / f"{candidate_id}.eml").read_bytes(), source_id=SOURCE_ID, campaign_id="opaque")
        evidence = triage_evidence(parsed, metadata)
        triage = triage_candidate(metadata, evidence)
        record, audit = build_derived_record(parsed, metadata, evidence)
        eligible, blockers = weak_label_eligibility(record, metadata, triage)
        audit["weak_label_eligible"] = eligible
        audit["eligibility_blockers"] = blockers
        derived.append(record)
        audits.append(audit)
        if eligible:
            eligibility_rows.append(record)
        for blocker in blockers:
            gate_exclusions[blocker] += 1
    existing_phishing = _existing_phishing_count(root)
    policy = WeakSamplingPolicy()
    sampled, cap_exclusions = sample_campaign_balanced(
        eligibility_rows, existing_phishing_train_rows=existing_phishing, policy=policy,
    )
    privacy_counts = Counter(item["privacy_status"] for item in audits)
    original_privacy_ids = {
        str(row["candidate_id"]) for row in metadata_rows
        if "address_in_decoded_content" in (row.get("privacy_flags") or [])
    }
    original_privacy_audits = [item for item in audits if item["candidate_id"] in original_privacy_ids]
    report_dir = root / "reports" / PILOT_ID
    derived_dir = root / "data" / "interim" / "phishing_pot_weak_label_preview"
    derived_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(derived_dir / "derived_records.jsonl", derived)
    policy_preview = {
        "schema_version": 1,
        "label_quality_taxonomy": list(LABEL_QUALITIES),
        "phishing_pot_assignment": {
            "label": WEAK_LABEL, "label_quality": WEAK_LABEL_QUALITY,
            "review_status": WEAK_REVIEW_STATUS, "split_role": "train_only",
        },
        "sampling_policy": asdict(policy),
        "boundary_policy": {
            "allowed": ["training"],
            "forbidden": ["validation", "test", "diagnostic", "calibration", "threshold_selection", "external_evaluation", "benchmark"],
            "violation_behavior": "hard_failure",
        },
        "source_policy_preview": {
            "proposed_development_mode": "weak_training_only",
            "registry_changed": False, "source_approved": False,
            "manual_approval_required": True,
            "manual_approval_steps": [
                "Review the generated privacy and eligibility audits.",
                "Confirm non-commercial research scope and CC BY-NC attribution.",
                "Explicitly amend the registry in a separate owner-approved change.",
            ],
            "restrictions": [
                "noncommercial_research_only", "attribution_required", "no_raw_redistribution",
                "no_raw_git_storage", "training_only", "sanitized_derived_records_only",
                "english_phishing_positive_only", "campaign_balanced_sampling_required",
            ],
        },
        "promotion_eligible": False, "training_executed": False,
    }
    audit_report = {
        "schema_version": 1, "assessed_candidates": len(audits),
        "privacy_status_counts": dict(sorted(privacy_counts.items())),
        "original_reject_privacy_count": len(original_privacy_audits),
        "original_reject_privacy_reprocessing": dict(sorted(Counter(item["privacy_status"] for item in original_privacy_audits).items())),
        "records": audits,
        "raw_content_included": False,
    }
    eligibility_report = {
        "schema_version": 1,
        "available_messages": 8612,
        "available_scope_note": "Local source inventory; only the 22-message staged pilot was parsed in this dry run.",
        "assessed_pilot_messages": len(derived),
        "safely_parsed": sum(bool(row.get("parse_safe")) for row in metadata_rows),
        "english": sum(str(row.get("language")) == "en" and float(row.get("language_confidence") or 0) >= .8 for row in metadata_rows),
        "privacy_sanitized": privacy_counts["privacy_sanitized"],
        "privacy_blocked": privacy_counts["privacy_blocked_irreducible"],
        "duplicate_exclusions": gate_exclusions["duplicate_or_external_boundary_conflict"],
        "insufficient_evidence_exclusions": gate_exclusions["insufficient_independent_evidence"],
        "attachment_only_exclusions": gate_exclusions["attachment_only"],
        "medium_or_non_high_exclusions": gate_exclusions["medium_or_non_high_triage"],
        "estimated_weak_label_eligible_rows": len(eligibility_rows),
        "gate_exclusion_counts": dict(sorted(gate_exclusions.items())),
        "scope": "staged_pilot_only_no_full_corpus_sampling",
    }
    final_count = len(sampled)
    sampling_report = {
        "schema_version": 1, "eligible_rows": len(eligibility_rows),
        "estimated_final_sampled_rows": final_count,
        "existing_phishing_training_rows": existing_phishing,
        "estimated_source_share": final_count / (existing_phishing + final_count) if existing_phishing + final_count else 0.0,
        "planned_sample_weight": policy.weak_sample_weight,
        "campaign_cap": policy.maximum_per_campaign, "template_cap": policy.maximum_per_template,
        "recognized_brand_share_cap": policy.maximum_per_recognized_brand_share,
        "source_share_cap": policy.maximum_source_share,
        "cap_exclusion_counts": cap_exclusions,
        "sampled_candidate_ids": [row["sample_id"] for row in sampled],
        "deterministic_seed": policy.deterministic_seed,
        "full_source_sampled": False,
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    payloads = {
        "phishing_pot_weak_label_policy.json": policy_preview,
        "phishing_pot_redaction_audit.json": audit_report,
        "phishing_pot_eligibility_dry_run.json": eligibility_report,
        "phishing_pot_sampling_estimate.json": sampling_report,
    }
    for name, payload in payloads.items():
        (report_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = [
        "# Phishing Pot weak-label policy preview", "",
        "Dry-run policy only. The source registry remains pending and no training or promotion occurred.", "",
        "## Assignment", "",
        "- Label: `phishing`", "- Label quality: `weak_source_provenance`",
        "- Review status: `not_manually_reviewed`", "- Permitted partition: training only",
        f"- Sample weight: `{policy.weak_sample_weight}`", "",
        "## Pilot estimate", "",
        f"- Privacy sanitized: {privacy_counts['privacy_sanitized']}",
        f"- Privacy blocked: {privacy_counts['privacy_blocked_irreducible']}",
        f"- Weak-label eligible: {len(eligibility_rows)}", f"- Campaign-balanced sample: {final_count}", "",
        "Manual owner approval is required in a separate change before setting `development_mode = weak_training_only`.", "",
    ]
    (report_dir / "phishing_pot_weak_label_policy.md").write_text("\n".join(markdown), encoding="utf-8")
    return {
        "policy": policy_preview, "redaction": audit_report,
        "eligibility": eligibility_report, "sampling": sampling_report,
        "derived_record_count": len(derived),
    }
