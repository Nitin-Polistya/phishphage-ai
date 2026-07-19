"""Deterministic, privacy-safe triage for the restricted Phishing Pot pilot.

Triage is advisory only.  It statically inspects locally staged messages, emits
only categorical/opaque evidence, and never records a reviewer decision or
authorizes ingestion, promotion, or training.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from .acquisition import parse_email_bytes
from .phishing_pot_pilot import PILOT_ID, SOURCE_ID, load_metadata_jsonl


TRIAGE_AUDIT_SEED = "phishing-pot-pilot-001-triage-audit-v1"
TRIAGE_OUTCOMES = frozenset({
    "high_confidence_phishing", "medium_confidence_review_required",
    "low_confidence_ambiguous", "spam_likely_not_phishing",
    "scam_likely_not_phishing", "malware_only_not_phishing",
    "reject_privacy", "reject_duplicate", "reject_non_english", "reject_corrupt",
})
INDEPENDENT_PHISHING_CATEGORIES = frozenset({
    "credential_request", "login_verification_request", "deceptive_action_request",
    "brand_impersonation", "sender_domain_mismatch", "reply_to_mismatch",
    "return_path_mismatch", "authentication_failure", "hidden_destination",
    "deceptive_destination", "visible_link_destination_mismatch", "suspicious_url",
    "account_threat", "invoice_deception", "payment_redirection", "bec_indicator", "qr_phishing",
})
EVIDENCE_GROUPS = {
    "credential_request": "credential_access_request",
    "login_verification_request": "credential_access_request",
    "deceptive_action_request": "suspicious_call_to_action",
    "brand_impersonation": "impersonation",
    "sender_domain_mismatch": "identity_path_mismatch",
    "reply_to_mismatch": "identity_path_mismatch",
    "return_path_mismatch": "identity_path_mismatch",
    "authentication_failure": "authentication_failure",
    "hidden_destination": "destination_deception",
    "deceptive_destination": "destination_deception",
    "visible_link_destination_mismatch": "destination_deception",
    "suspicious_url": "destination_deception",
    "account_threat": "account_threat",
    "invoice_deception": "invoice_lure",
    "payment_redirection": "payment_or_bec_deception",
    "bec_indicator": "payment_or_bec_deception",
    "qr_phishing": "qr_phishing",
}
NON_BLOCKING_PRIVACY_FLAGS = frozenset({"address_in_header"})
BLOCKING_PRIVACY_FLAGS = frozenset({
    "address_in_decoded_content", "sensitive_url_parameters_require_review",
    "sensitive_html_attribute_requires_review", "sensitive_attachment_name_requires_review",
    "safe_parse_failed",
})

PATTERNS = {
    "credential_request": re.compile(r"(?i)\b(?:enter|provide|confirm|validate|update|reset)\b.{0,55}\b(?:password|credentials?|user\s*name|passcode|pin)\b|\b(?:password|credentials?)\b.{0,35}\b(?:required|expire|verify)\b"),
    "login_verification_request": re.compile(r"(?i)\b(?:sign|log)[ -]?in\b|\b(?:verify|validate|confirm)\b.{0,40}\b(?:account|identity|mailbox)\b"),
    "deceptive_action_request": re.compile(r"(?i)\b(?:click|follow|open|scan)\b.{0,40}\b(?:link|button|below|qr|code)\b"),
    "generic_urgency": re.compile(r"(?i)\b(?:urgent|immediately|action required|final notice|within (?:\d+|twenty-four) hours?)\b"),
    "account_threat": re.compile(r"(?i)\b(?:account|mailbox|access)\b.{0,55}\b(?:suspend|disable|lock|terminate|expire|restricted?)\w*\b|\b(?:suspend|disable|lock|terminate)\w*\b.{0,40}\b(?:account|mailbox|access)\b"),
    "payment_redirection": re.compile(r"(?i)\b(?:wire|bank details|payment|remittance|invoice)\b.{0,65}\b(?:send|transfer|change|new|overdue|pay)\b|\b(?:send|transfer|pay)\b.{0,45}\b(?:funds|invoice|payment)\b"),
    "invoice_deception": re.compile(r"(?i)\b(?:invoice|purchase order|remittance advice)\b.{0,70}\b(?:attached|review|open|overdue|outstanding|payment)\b|\b(?:attached|review|open)\b.{0,45}\binvoice\b"),
    "bec_indicator": re.compile(r"(?i)\b(?:payroll|direct deposit|gift cards?|wire transfer|bank details|ceo|chief executive)\b"),
    "qr_phishing": re.compile(r"(?i)\b(?:qr|q\.r\.)\s*(?:code)?\b.{0,50}\b(?:scan|login|verify|payment)\b|\bscan\b.{0,35}\bqr\b"),
    "spam_only": re.compile(r"(?i)\b(?:unsubscribe|limited time offer|buy now|weight loss|casino|lottery|special offer)\b"),
    "scam_only": re.compile(r"(?i)\b(?:inheritance|advance fee|lottery winner|charity donation|investment return)\b"),
}
BRANDS = ("microsoft", "office 365", "google", "gmail", "apple", "amazon", "paypal", "dhl", "fedex", "ups", "adobe", "dropbox", "linkedin", "netflix", "facebook", "instagram")
SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"})
SUSPICIOUS_TLDS = frozenset({"zip", "mov", "click", "top", "xyz", "work", "support", "live", "cam", "rest", "gq", "tk"})


def _host(url: str) -> str:
    candidate = url.strip()
    if not re.match(r"(?i)^https?://", candidate):
        candidate = "https://" + candidate
    try:
        return (urllib.parse.urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _aligned(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def _brand_bucket(text: str, metadata: Mapping[str, Any]) -> str:
    for brand in BRANDS:
        if re.search(rf"(?i)\b{re.escape(brand)}\b", text):
            return "brand-" + hashlib.sha256(brand.encode()).hexdigest()[:12]
    return str(metadata.get("brand_group") or "brand-unknown")


def triage_evidence(
    parsed: Mapping[str, Any], metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive categorical signals from a safe local parse; no values are emitted."""
    metadata = metadata or {}
    text = str(parsed.get("text") or "")[:250_000]
    sender = str(parsed.get("sender_domain") or "").lower()
    reply_to = str(parsed.get("reply_to_domain") or "").lower()
    urls = [str(item) for item in parsed.get("urls") or []]
    url_hosts = [_host(item) for item in urls]
    url_hosts = [item for item in url_hosts if item]
    attachments = list(parsed.get("attachments") or [])
    body_present = bool(re.sub(r"(?is)^subject:.*?\n", "", text).strip())
    result: dict[str, Any] = {
        key: bool(pattern.search(text)) for key, pattern in PATTERNS.items()
    }
    result["reply_to_mismatch"] = bool(sender and reply_to and not _aligned(sender, reply_to))
    result["sender_domain_mismatch"] = bool(sender and url_hosts and all(not _aligned(sender, host) for host in url_hosts))
    result["suspicious_url"] = any(
        host.startswith("xn--") or host in SHORTENERS or host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS
        or url.count("@") > 0 or len(host.split(".")) >= 5
        for url, host in zip(urls, url_hosts)
    )
    result["deceptive_destination"] = bool(
        url_hosts and (result["sender_domain_mismatch"] or result["suspicious_url"])
        and (result["deceptive_action_request"] or result["login_verification_request"])
    )
    auth_values = " ".join(
        str(value) for values in (parsed.get("authentication_headers") or {}).values()
        for value in (values if isinstance(values, list) else [values])
    )
    result["authentication_failure"] = bool(re.search(r"(?i)\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail|temperror|permerror)\b", auth_values))
    brand_mentions = [brand for brand in BRANDS if re.search(rf"(?i)\b{re.escape(brand)}\b", text)]
    result["brand_impersonation"] = bool(brand_mentions and sender and all(brand.replace(" ", "") not in sender.replace("-", "") for brand in brand_mentions))
    message_level_action = any(result.get(name) for name in (
        "credential_request", "login_verification_request", "deceptive_action_request",
        "account_threat", "payment_redirection", "bec_indicator", "qr_phishing",
    )) or bool(url_hosts)
    # "Attachment-only" includes a short cover note whose asserted payload
    # cannot be verified without opening the attachment.  Such a row must stay
    # out of high-confidence triage even when its headers look suspicious.
    result["attachment_only"] = bool(attachments and (not body_present or not message_level_action))
    result["attachment_present"] = bool(attachments)
    result["malware_attachment_indicator"] = any(
        str(item.get("content_type") or "").lower() in {"application/x-msdownload", "application/x-dosexec"}
        or Path(str(item.get("filename") or "")).suffix.lower() in {".exe", ".scr", ".js", ".vbs", ".iso", ".lnk"}
        for item in attachments
    )
    result["language_confidence"] = float(metadata.get("language_confidence") or 0.0)
    result["brand_bucket"] = _brand_bucket(text, metadata)
    theme = str(metadata.get("theme_group") or "other")
    result["phishing_family"] = (
        "credential_harvest" if result["credential_request"] or result["login_verification_request"]
        else "payment_bec" if result["payment_redirection"] or result["bec_indicator"]
        else "qr_phishing" if result["qr_phishing"]
        else "account_threat" if result["account_threat"]
        else "attachment_lure" if attachments
        else theme
    )
    return result


def _true_categories(evidence: Mapping[str, Any]) -> set[str]:
    return {key for key, value in evidence.items() if value is True and key not in {"attachment_present"}}


def triage_candidate(metadata: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Assign exactly one advisory outcome to an opaque candidate."""
    candidate_id = str(metadata.get("candidate_id") or "")
    categories = _true_categories(evidence)
    privacy_flags = set(str(item) for item in metadata.get("privacy_flags") or [])
    privacy_blocked = bool(metadata.get("privacy_unresolved")) or bool(privacy_flags & BLOCKING_PRIVACY_FLAGS)
    duplicate = metadata.get("internal_duplicate_status") == "duplicate" or metadata.get("boundary_overlap") is True
    corrupt = metadata.get("parse_safe") is not True or metadata.get("malformed") is True
    non_english = str(metadata.get("language") or "").lower() != "en"
    attachment_only = "attachment_only" in categories
    corroborating = sorted(categories & INDEPENDENT_PHISHING_CATEGORIES)
    evidence_groups = sorted({EVIDENCE_GROUPS[item] for item in corroborating})
    contradictions: list[str] = []
    if attachment_only:
        contradictions.append("attachment_only_requires_manual_inspection")
    if evidence.get("spam_only"):
        contradictions.append("generic_spam_characteristics")
    if evidence.get("scam_only"):
        contradictions.append("generic_scam_characteristics")
    if float(metadata.get("language_confidence") or evidence.get("language_confidence") or 0) < 0.80:
        contradictions.append("low_language_confidence")

    if corrupt:
        outcome, reason, action = "reject_corrupt", "Static parsing was defective or unsafe.", "reject_candidate"
    elif non_english:
        outcome, reason, action = "reject_non_english", "The candidate is outside the English-primary scope.", "reject_candidate"
    elif duplicate:
        outcome, reason, action = "reject_duplicate", "Duplicate or protected-boundary overlap was detected.", "reject_candidate"
    elif privacy_blocked:
        outcome, reason, action = "reject_privacy", "Decoded-content or unresolved privacy evidence requires human review.", "manual_privacy_review"
    elif attachment_only and evidence.get("malware_attachment_indicator"):
        outcome, reason, action = "malware_only_not_phishing", "Attachment metadata suggests malware, but message-level phishing intent is uncorroborated.", "manual_taxonomy_review"
    elif attachment_only:
        outcome, reason, action = "medium_confidence_review_required", "Attachment-only behavior cannot establish phishing without opening the attachment.", "manual_content_and_taxonomy_review"
    elif len(evidence_groups) >= 2 and not contradictions:
        outcome, reason, action = "high_confidence_phishing", "At least two independent phishing evidence categories corroborate one another.", "policy_gated_spot_review_or_hold"
    elif evidence.get("spam_only") and not corroborating:
        outcome, reason, action = "spam_likely_not_phishing", "Generic spam characteristics lack corroborating phishing behavior.", "exclude_or_manual_taxonomy_review"
    elif evidence.get("scam_only") and not corroborating:
        outcome, reason, action = "scam_likely_not_phishing", "Generic scam characteristics lack corroborating phishing behavior.", "exclude_or_manual_taxonomy_review"
    elif corroborating or len(categories & {"generic_urgency", "brand_impersonation", "suspicious_url"}) >= 2:
        outcome, reason, action = "medium_confidence_review_required", "Suspicious evidence is present but does not meet strict independent corroboration.", "manual_phishing_review"
    else:
        outcome, reason, action = "low_confidence_ambiguous", "Evidence is too weak or nonspecific for a phishing label.", "manual_taxonomy_review_or_exclude"

    weights = {
        "credential_request": 24, "login_verification_request": 18,
        "deceptive_action_request": 13, "deceptive_destination": 24,
        "visible_link_destination_mismatch": 24, "hidden_destination": 22,
        "brand_impersonation": 10, "sender_domain_mismatch": 12,
        "reply_to_mismatch": 12, "return_path_mismatch": 10,
        "authentication_failure": 14, "suspicious_url": 9, "account_threat": 16,
        "invoice_deception": 16, "payment_redirection": 22, "bec_indicator": 18,
        "qr_phishing": 22,
        "generic_urgency": 5,
    }
    score = max(0, min(100, sum(weights.get(item, 0) for item in categories) - 10 * len(contradictions)))
    confidence = (
        0.95 if outcome == "high_confidence_phishing" else
        0.90 if outcome.startswith("reject_") else
        0.78 if outcome == "medium_confidence_review_required" else 0.65
    )
    return {
        "candidate_id": candidate_id,
        "provisional_outcome": outcome,
        "triage_score": score,
        "supporting_evidence_categories": sorted(categories),
        "corroborating_phishing_categories": corroborating,
        "independent_evidence_groups": evidence_groups,
        "contradictory_evidence": sorted(contradictions),
        "confidence": confidence,
        "reason": reason,
        "required_next_action": action,
        "phishing_family": str(evidence.get("phishing_family") or metadata.get("theme_group") or "unknown"),
        "brand_bucket": str(evidence.get("brand_bucket") or metadata.get("brand_group") or "brand-unknown"),
        "campaign_group": str(metadata.get("campaign_group") or "campaign-unknown"),
        "template_group": str(metadata.get("template_group") or "template-unknown"),
        "privacy_review_required": privacy_blocked,
        "promotion_eligible": False,
        "automated_triage_only": True,
        "reviewer_decision": None,
    }


def _rank(seed: str, candidate_id: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{candidate_id}".encode()).hexdigest()


def _review_command(candidate_id: str) -> str:
    return (
        "python services/ml/scripts/review_phishing_pot_candidate.py `\n"
        f"  --candidate-id {candidate_id} `\n"
        "  --classification ambiguous `\n"
        "  --reviewer \"NITIN\" `\n"
        "  --privacy-checks-passed `\n"
        "  --license-checks-passed `\n"
        "  --grouping-reviewed"
    )


def build_review_shortlist(
    results: Iterable[Mapping[str, Any]], *, seed: str = TRIAGE_AUDIT_SEED,
    audit_rate: float = 0.20,
) -> dict[str, Any]:
    """Build a deterministic union of mandatory review and coverage samples."""
    if not 0 <= audit_rate <= 1:
        raise ValueError("audit_rate must be between 0 and 1")
    rows = sorted((dict(item) for item in results), key=lambda item: str(item["candidate_id"]))
    high = [item for item in rows if item["provisional_outcome"] == "high_confidence_phishing"]
    reasons: dict[str, set[str]] = {str(item["candidate_id"]): set() for item in rows}
    for item in rows:
        cid = str(item["candidate_id"])
        if item["provisional_outcome"] == "medium_confidence_review_required":
            reasons[cid].add("medium_confidence")
        if item["provisional_outcome"] == "high_confidence_phishing" and item.get("contradictory_evidence"):
            reasons[cid].add("contradictory_high_confidence")
        if item.get("privacy_review_required"):
            reasons[cid].add("privacy_flagged")

    audit_count = math.ceil(len(high) * audit_rate) if high else 0
    audit = sorted(high, key=lambda item: _rank(seed, str(item["candidate_id"])))[:audit_count]
    for item in audit:
        reasons[str(item["candidate_id"])].add("deterministic_20_percent_spot_audit")

    def cover(field: str, marker: str, values: set[str]) -> None:
        for value in sorted(values):
            candidates = [item for item in rows if str(item.get(field)) == value]
            if not candidates:
                continue
            already = next((item for item in candidates if reasons[str(item["candidate_id"])]), None)
            chosen = already or min(candidates, key=lambda item: _rank(seed + marker, str(item["candidate_id"])))
            reasons[str(chosen["candidate_id"])].add(marker)

    families = {str(item.get("phishing_family") or "unknown") for item in rows}
    cover("phishing_family", "phishing_family_coverage", families)
    brand_counts = Counter(str(item.get("brand_bucket") or "brand-unknown") for item in rows)
    major_brands = {brand for brand, count in brand_counts.items() if brand != "brand-unknown" and count >= 2}
    cover("brand_bucket", "major_brand_coverage", major_brands)

    selected = []
    for item in rows:
        cid = str(item["candidate_id"])
        if not reasons[cid]:
            continue
        selected.append({
            "candidate_id": cid,
            "provisional_outcome": item["provisional_outcome"],
            "confidence": item["confidence"],
            "evidence_categories": list(item.get("supporting_evidence_categories") or []),
            "manual_review_reasons": sorted(reasons[cid]),
            "phishing_family": item["phishing_family"],
            "brand_bucket": item["brand_bucket"],
            "campaign_group": item["campaign_group"],
            "template_group": item["template_group"],
            "review_command": _review_command(cid),
        })
    return {
        "schema_version": 1,
        "audit_seed": seed,
        "audit_rate": audit_rate,
        "high_confidence_count": len(high),
        "spot_audit_candidate_ids": sorted(str(item["candidate_id"]) for item in audit),
        "covered_phishing_families": sorted(families),
        "covered_major_brand_buckets": sorted(major_brands),
        "count": len(selected),
        "candidate_ids": [item["candidate_id"] for item in selected],
        "candidates": selected,
    }


def _source_quality(counts: Counter[str], total: int) -> dict[str, str]:
    promising = counts["high_confidence_phishing"] / total if total else 0
    unsuitable = sum(counts[name] for name in (
        "spam_likely_not_phishing", "scam_likely_not_phishing",
        "malware_only_not_phishing", "reject_duplicate", "reject_non_english", "reject_corrupt",
    )) / total if total else 1
    estimate = "likely promising" if promising >= 0.60 and unsuitable <= 0.20 else "likely unsuitable" if unsuitable >= 0.50 else "uncertain"
    return {
        "estimate": estimate,
        "qualification": "Automated, provisional, selection-biased pilot-yield estimate; not source approval.",
    }


def triage_staged_pilot(root: Path, *, policy: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Triage the exact staged manifest and return report, shortlist, spot audit."""
    stage = root / "data" / "staging" / PILOT_ID
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    metadata_rows = load_metadata_jsonl(stage / "validation" / "selected_metadata.jsonl")
    by_id = {str(item["candidate_id"]): item for item in metadata_rows}
    selected_ids = [str(item) for item in manifest["selected_candidate_ids"]]
    if set(selected_ids) != set(by_id) or len(selected_ids) != 22:
        raise ValueError("Staged manifest and selected metadata do not describe the exact 22-candidate pilot")
    results = []
    for cid in selected_ids:
        raw_path = stage / "raw" / f"{cid}.eml"
        parsed = parse_email_bytes(raw_path.read_bytes(), source_id=SOURCE_ID, campaign_id="opaque")
        evidence = triage_evidence(parsed, by_id[cid])
        results.append(triage_candidate(by_id[cid], evidence))
    counts = Counter(item["provisional_outcome"] for item in results)
    shortlist = build_review_shortlist(results)
    allowed = bool((policy or {}).get("automated_triage_allowed_for_training", False))
    report = {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "candidate_count": len(results), "outcome_counts": dict(sorted(counts.items())),
        "high_confidence_count": counts["high_confidence_phishing"],
        "automatic_rejection_count": sum(value for name, value in counts.items() if name.startswith("reject_")),
        "manual_review_count": shortlist["count"], "source_quality": _source_quality(counts, len(results)),
        "automated_triage_allowed_for_training": allowed,
        "provisional_training_eligibility_count": 0,
        "promotion_eligible": False, "reviewer_decisions_recorded": 0,
        "results": results,
        "triage_policy": {
            "version": "static-categorical-v1",
            "high_confidence_minimum_independent_evidence_groups": 2,
            "semantically_related_signals_count_once": True,
            "brand_identity_alone_is_sufficient": False,
            "deterministic_audit_seed": TRIAGE_AUDIT_SEED,
            "raw_content_in_reports": False,
        },
        "safety": {"html_rendered": False, "links_fetched": False, "attachments_opened": False},
    }
    spot = {
        "schema_version": 1, "pilot_id": PILOT_ID, "seed": shortlist["audit_seed"],
        "rate": shortlist["audit_rate"], "candidate_ids": shortlist["spot_audit_candidate_ids"],
        "promotion_eligible": False,
    }
    return report, shortlist, spot


def triage_markdown(report: Mapping[str, Any]) -> str:
    lines = ["# Phishing Pot automated triage", "", "Automated and provisional; this is not a reviewer decision or source approval.", "", "## Summary", ""]
    lines.extend(f"- `{name}`: {count}" for name, count in report["outcome_counts"].items())
    lines.extend(["", f"- Manual review shortlist: {report['manual_review_count']}", f"- Source-quality estimate: **{report['source_quality']['estimate']}**", "- Promotion eligible: no", ""])
    return "\n".join(lines)


def shortlist_markdown(shortlist: Mapping[str, Any]) -> str:
    lines = ["# Phishing Pot manual-review shortlist", "", f"Deterministic audit seed: `{shortlist['audit_seed']}`", ""]
    for item in shortlist["candidates"]:
        evidence = ", ".join(item["evidence_categories"]) or "none"
        lines.extend([
            f"## `{item['candidate_id']}`", "",
            f"- Outcome: `{item['provisional_outcome']}`",
            f"- Confidence: {item['confidence']:.2f}",
            f"- Evidence: {evidence}",
            f"- Reasons: {', '.join(item['manual_review_reasons'])}",
            f"- Family: `{item['phishing_family']}`",
            f"- Brand bucket: `{item['brand_bucket']}`",
            f"- Campaign group: `{item['campaign_group']}`",
            f"- Template group: `{item['template_group']}`", "",
            "Run only after independently verifying the listed privacy and license checks:", "",
            "```powershell", item["review_command"], "```", "",
        ])
    return "\n".join(lines)


def write_triage_reports(root: Path, output_dir: Path, *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    report, shortlist, spot = triage_staged_pilot(root, policy=policy)
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads = {
        "phishing_pot_triage.json": report,
        "phishing_pot_review_shortlist.json": shortlist,
        "phishing_pot_spot_audit.json": spot,
    }
    for name, payload in payloads.items():
        (output_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "phishing_pot_triage.md").write_text(triage_markdown(report), encoding="utf-8")
    (output_dir / "phishing_pot_review_shortlist.md").write_text(shortlist_markdown(shortlist), encoding="utf-8")
    return report
