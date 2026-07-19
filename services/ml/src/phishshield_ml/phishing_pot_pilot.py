"""Privacy-safe planning helpers for the restricted Phishing Pot pilot.

This module operates on registry, pilot configuration, and privacy-safe
metadata. Its scanner may statically parse local EML files through the guarded
parser; it never renders HTML, contacts message-derived resources, persists
message content, opens attachments, or authorizes ingestion or promotion.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from .acquisition import MAX_MESSAGE_BYTES, parse_email_bytes
from .controlled_acquisition import (
    load_controlled_registry,
    pilot_promotion_eligibility,
    validate_source_for_development,
)
from .dataset import canonicalize_template, estimate_language
from .generalization import _simhash


SOURCE_ID = "github_rf_peixoto_phishing_pot"
PILOT_ID = "phishing_pot_pilot_001"
PLANNED_COUNT = 22
SELECTION_SEED = "phishing-pot-pilot-001-v1"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAFE_BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
BRAND_TERMS = (
    "microsoft", "office 365", "outlook", "google", "gmail", "apple",
    "amazon", "paypal", "dhl", "fedex", "ups", "adobe", "dropbox",
    "linkedin", "netflix", "facebook", "instagram", "bank of america",
)
THEME_PATTERNS = {
    "credential": re.compile(r"(?i)\b(?:password|credential|sign[ -]?in|log[ -]?in|verify identity|webmail)\b"),
    "account_security": re.compile(r"(?i)\b(?:account|security|suspend|locked|unusual activity|expire)\b"),
    "invoice_payment": re.compile(r"(?i)\b(?:invoice|payment|payroll|wire transfer|remittance|purchase order)\b"),
    "shipping": re.compile(r"(?i)\b(?:delivery|shipment|parcel|courier|tracking)\b"),
    "mfa_otp": re.compile(r"(?i)\b(?:one[ -]?time|otp|mfa|2fa|verification code)\b"),
}
URGENCY_RE = re.compile(r"(?i)\b(?:urgent|immediately|within \d+ hours?|final notice|action required)\b")
ENGLISH_HINTS = frozenset({
    "the", "and", "your", "you", "to", "of", "for", "is", "in", "this",
    "that", "with", "from", "account", "please", "click", "email", "will",
    "have", "has", "our", "we", "security", "message", "verify", "login",
})


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})


def build_preflight_validation(root: Path) -> dict[str, Any]:
    """Validate that pilot staging is restricted and promotion stays blocked."""
    registry_path = root / "config" / "dataset_source_registry.json"
    pilot_path = root / "config" / "acquisition_batches" / f"{PILOT_ID}.json"
    batch_path = root / "config" / "acquisition_batches" / "batch_001.json"
    _, sources = load_controlled_registry(registry_path)
    source = sources[SOURCE_ID]
    pilot = _load_json(pilot_path)
    batch = _load_json(batch_path)
    checks: list[dict[str, Any]] = []

    _check(checks, "staging_allowed", source.get("staging_allowed") is True, "must be true")
    _check(checks, "development_disabled", source.get("development_allowed") is False, "must be false")
    _check(checks, "source_pending", source.get("approval_status") == "pending", "must remain pending")
    _check(
        checks, "restricted_license_verified",
        source.get("license_status") == "verified_restricted_noncommercial",
        "must be verified_restricted_noncommercial",
    )
    _check(
        checks, "sample_privacy_review_required",
        source.get("privacy_status") == "pending_sample_review",
        "must be pending_sample_review",
    )
    _check(checks, "raw_redistribution_disabled", source.get("redistribution_allowed") is False, "must be false")
    _check(checks, "raw_storage_disabled", source.get("raw_storage_allowed") is False, "must be false")
    _check(checks, "ingestion_disabled", source.get("ingestion_enabled") is False, "must be false")
    _check(checks, "pilot_id", pilot.get("pilot_id") == PILOT_ID, "pilot ID must match")
    _check(checks, "pilot_staging_only", pilot.get("staging_only") is True, "must be true")
    _check(
        checks, "planned_candidate_count",
        pilot.get("planned_candidate_count") == PLANNED_COUNT,
        f"must equal {PLANNED_COUNT}",
    )
    batch_row = next(
        (row for row in batch.get("source_distribution", []) if row.get("source_id") == SOURCE_ID),
        {},
    )
    _check(
        checks, "batch_candidate_count", batch_row.get("planned_count") == PLANNED_COUNT,
        f"Batch 001 must reserve exactly {PLANNED_COUNT} rows",
    )

    gitignore = (root.parents[1] / ".gitignore").read_text(encoding="utf-8").splitlines()
    ignore_rules = {line.strip().replace("\\", "/") for line in gitignore if line.strip() and not line.startswith("#")}
    _check(
        checks, "external_acquisition_gitignored",
        "services/ml/data/external/*" in ignore_rules,
        "services/ml/data/external/* must be ignored",
    )
    _check(
        checks, "raw_staging_gitignored",
        "services/ml/data/staging/*" in ignore_rules,
        "services/ml/data/staging/* must be ignored",
    )
    required_scripts = ("ingest_batch.py", "review_batch.py", "promote_batch.py")
    _check(
        checks, "controlled_workflow_scripts_present",
        all((root / "scripts" / name).is_file() for name in required_scripts),
        "ingestion, review, and promotion entrypoints must exist",
    )

    development_blocked = False
    try:
        validate_source_for_development(source)
    except PermissionError:
        development_blocked = True
    _check(checks, "development_gate_blocks_source", development_blocked, "pending source must fail development gate")
    eligibility = pilot_promotion_eligibility(source, {
        "classification": "phishing", "manual_approved": False,
        "phishing_confirmed": False, "language": "en",
        "privacy_checks_passed": False, "duplicate_checks_passed": False,
        "overlap_checks_passed": False, "campaign_group": None, "template_group": None,
    })
    _check(
        checks, "promotion_blocked", eligibility["eligible"] is False,
        "pending source and incomplete sample review must be promotion-ineligible",
    )
    blockers = sorted(set(eligibility["reasons"]))
    report = {
        "schema_version": 1,
        "pilot_id": PILOT_ID,
        "source_id": SOURCE_ID,
        "planned_candidate_count": PLANNED_COUNT,
        "checks": checks,
        "passed": all(item["passed"] for item in checks),
        "promotion_eligible": False,
        "promotion_blockers": blockers,
        "acquisition_authorized_by_report": False,
        "privacy_note": "No email content or source samples were inspected by this preflight.",
    }
    return report


def preflight_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phishing Pot Pilot Preflight", "",
        f"- Pilot: `{report['pilot_id']}`",
        f"- Source: `{report['source_id']}`",
        f"- Result: **{'PASS' if report['passed'] else 'FAIL'}**",
        f"- Planned candidates: {report['planned_candidate_count']}",
        "- Promotion eligible: no", "",
        "| Check | Result | Requirement |", "|---|---|---|",
    ]
    for item in report["checks"]:
        lines.append(f"| `{item['check']}` | {'pass' if item['passed'] else 'FAIL'} | {item['detail']} |")
    lines.extend([
        "", "## Promotion blockers", "",
        *(f"- `{reason}`" for reason in report["promotion_blockers"]),
        "", "This report contains no message content and does not authorize acquisition, ingestion, promotion, or training.", "",
    ])
    return "\n".join(lines)


def write_preflight_validation(root: Path, output_dir: Path) -> dict[str, Any]:
    report = build_preflight_validation(root)
    _write_json(output_dir / "preflight_validation.json", report)
    (output_dir / "preflight_validation.md").write_text(preflight_markdown(report), encoding="utf-8")
    if not report["passed"]:
        failed = ", ".join(item["check"] for item in report["checks"] if not item["passed"])
        raise ValueError(f"Phishing Pot pilot preflight failed: {failed}")
    return report


def _safe_identifier(value: Any, field: str) -> str:
    text = str(value or "")
    if not SAFE_ID_RE.fullmatch(text) or "@" in text:
        raise ValueError(f"{field} must be an opaque privacy-safe identifier")
    return text


def _safe_bucket(value: Any) -> str:
    text = str(value or "unknown")
    if ".." in text or "@" in text or not SAFE_BUCKET_RE.fullmatch(text):
        return "redacted_or_unknown"
    return text


def _opaque_group(prefix: str, *values: str) -> str:
    material = "\x1f".join(value.lower().strip() for value in values if value)
    return f"{prefix}-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def _url_host(value: str) -> str:
    candidate = re.sub(r"(?i)^hxxps?://", "https://", value.strip())
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    try:
        return (urllib.parse.urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _period_bucket(relative: Path) -> str:
    parts = [part.lower() for part in relative.parts[:-1]]
    for index, part in enumerate(parts):
        if re.fullmatch(r"20\d{2}", part):
            month = parts[index + 1] if index + 1 < len(parts) and re.fullmatch(r"(?:0?[1-9]|1[0-2])", parts[index + 1]) else None
            return f"{part}/{int(month):02d}" if month else part
    return "unknown"


def _provisional_taxonomy(text: str, *, has_url: bool, reply_mismatch: bool) -> tuple[str, list[str], bool]:
    themes = [name for name, pattern in THEME_PATTERNS.items() if pattern.search(text)]
    theme = themes[0] if themes else "other"
    basis: list[str] = []
    if has_url:
        basis.append("url_present")
    if reply_mismatch:
        basis.append("reply_to_mismatch")
    if URGENCY_RE.search(text):
        basis.append("urgency_language")
    basis.extend(f"theme:{name}" for name in themes)
    strong_lure = any(name in themes for name in ("credential", "mfa_otp", "invoice_payment"))
    provisional = (has_url and strong_lure) or (reply_mismatch and strong_lure) or (
        has_url and bool(themes) and "urgency_language" in basis
    )
    return theme, basis, provisional


def _brand_group(text: str) -> str:
    matches = [term for term in BRAND_TERMS if re.search(rf"(?i)\b{re.escape(term)}\b", text)]
    return _opaque_group("brand", matches[0]) if matches else "brand-unknown"


def _estimate_language_for_inventory(text: str) -> tuple[str, float, str]:
    """Fast-path obvious English prose, falling back to deterministic langdetect."""
    sample = text[:10000]
    words = re.findall(r"[a-z]+", sample.lower())
    hint_count = sum(word in ENGLISH_HINTS for word in words)
    alphabetic = [character for character in sample if character.isalpha()]
    ascii_ratio = (
        sum(character.isascii() for character in alphabetic) / len(alphabetic)
        if alphabetic else 0.0
    )
    if len(words) >= 12 and hint_count >= 3 and ascii_ratio >= 0.9:
        return "en", min(0.99, 0.85 + 0.01 * hint_count), "english_hint_fast_path"
    language, confidence = estimate_language(sample)
    return language, confidence, "langdetect"


def derive_safe_eml_metadata(raw: bytes, *, relative_path: Path) -> dict[str, Any]:
    """Parse one untrusted EML and return only opaque or aggregate metadata."""
    raw_hash = hashlib.sha256(raw).hexdigest()
    candidate_id = _opaque_group("candidate", relative_path.as_posix(), raw_hash)
    base: dict[str, Any] = {
        "candidate_id": candidate_id,
        "sha256": raw_hash,
        "source_bytes": len(raw),
        "period_bucket": _period_bucket(relative_path),
        "source": SOURCE_ID,
    }
    try:
        parsed = parse_email_bytes(raw, source_id=SOURCE_ID, campaign_id="opaque")
    except (ValueError, TypeError, UnicodeError) as exc:
        return {
            **base,
            "parse_safe": False,
            "malformed": True,
            "parse_error_category": type(exc).__name__,
            "language": "unknown",
            "language_confidence": 0.0,
            "mime_types": [],
            "attachment_count": 0,
            "attachment_total_bytes": 0,
            "attachment_hashes": [],
            "privacy_flags": ["safe_parse_failed"],
            "privacy_unresolved": True,
            "privacy_review_required": True,
            "phishing_intent": False,
            "provisional_intent_basis": [],
        }

    text = str(parsed["text"])
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    canonical = canonicalize_template(text)
    normalized_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    language, confidence, language_method = _estimate_language_for_inventory(text)
    sender_domain = str(parsed.get("sender_domain") or "")
    reply_domain = str(parsed.get("reply_to_domain") or "")
    url_hosts = sorted({host for host in (_url_host(url) for url in parsed.get("urls", [])) if host})
    reply_mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    theme, intent_basis, phishing_intent = _provisional_taxonomy(
        text, has_url=bool(parsed.get("urls")), reply_mismatch=reply_mismatch,
    )
    infrastructure = _opaque_group("infra", sender_domain, reply_domain, *url_hosts)
    campaign = _opaque_group("campaign", infrastructure, theme, canonical[:256])
    attachments = parsed.get("attachments") or []
    privacy_flags = sorted(set(parsed.get("privacy", {}).get("flags") or []))
    unresolved_flags = {
        "sensitive_url_parameters_require_review",
        "sensitive_html_attribute_requires_review",
        "sensitive_attachment_name_requires_review",
    }
    return {
        **base,
        "parse_safe": True,
        "malformed": bool(parsed.get("malformed")),
        "parse_warning_categories": sorted(set(parsed.get("parse_warnings") or [])),
        "language": language,
        "language_confidence": round(confidence, 6),
        "language_method": language_method,
        "mime_types": sorted(set(parsed.get("mime_types") or [])),
        "attachment_count": len(attachments),
        "attachment_total_bytes": sum(max(0, int(item.get("bytes") or 0)) for item in attachments),
        "attachment_hashes": sorted(str(item.get("sha256")) for item in attachments if item.get("sha256")),
        "attachment_content_types": sorted({str(item.get("content_type") or "application/octet-stream") for item in attachments}),
        "content_hash": content_hash,
        "normalized_hash": normalized_hash,
        "simhash": f"{_simhash(text):016x}",
        "template_group": f"template-{normalized_hash[:20]}",
        "campaign_group": campaign,
        "sender_infrastructure_group": infrastructure,
        "brand_group": _brand_group(text),
        "theme_group": theme,
        "has_header_evidence": bool(sender_domain or reply_domain),
        "has_authentication_evidence": bool(parsed.get("authentication_headers")),
        "has_url_evidence": bool(parsed.get("urls")),
        "remote_resources_blocked": max(0, int(parsed.get("remote_resources_blocked") or 0)),
        "privacy_flags": privacy_flags,
        "privacy_unresolved": bool(unresolved_flags.intersection(privacy_flags)),
        "privacy_review_required": bool(privacy_flags),
        "phishing_intent": phishing_intent,
        "provisional_intent_basis": intent_basis,
        "boundary_overlap": None,
        "boundary_overlap_status": "not_yet_compared",
    }


def _scan_eml_path(arguments: tuple[str, str]) -> dict[str, Any]:
    path_text, root_text = arguments
    path = Path(path_text)
    root = Path(root_text)
    relative = path.relative_to(root)
    try:
        size = path.stat().st_size
        if size > MAX_MESSAGE_BYTES:
            raise ValueError("message_too_large")
        return derive_safe_eml_metadata(path.read_bytes(), relative_path=relative)
    except Exception as exc:
        try:
            size = max(0, path.stat().st_size)
        except OSError:
            size = 0
        return {
            "candidate_id": _opaque_group("candidate", relative.as_posix(), str(size)),
            "source": SOURCE_ID, "source_bytes": size,
            "period_bucket": _period_bucket(relative), "parse_safe": False,
            "malformed": True, "parse_error_category": type(exc).__name__,
            "language": "unknown", "language_confidence": 0.0,
            "language_method": "unavailable", "mime_types": [],
            "attachment_count": 0, "privacy_flags": ["safe_parse_failed"],
            "privacy_unresolved": True, "privacy_review_required": True,
            "phishing_intent": False, "provisional_intent_basis": [],
            "boundary_overlap": None, "boundary_overlap_status": "not_yet_compared",
        }


def scan_eml_directory(directory: Path, *, workers: int = 1) -> Iterable[dict[str, Any]]:
    """Yield privacy-safe metadata for local EML files without following symlinks."""
    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"EML scan root is not a directory: {directory}")
    if workers < 1:
        raise ValueError("workers must be at least 1")
    paths: list[Path] = []
    for path in sorted(
        (item for item in directory.rglob("*") if item.suffix.lower() == ".eml"),
        key=lambda item: item.as_posix().lower(),
    ):
        if path.is_symlink() or not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError("EML path escaped the configured scan root")
        paths.append(resolved)
    arguments = [(str(path), str(root)) for path in paths]
    if workers == 1:
        for argument in arguments:
            yield _scan_eml_path(argument)
        return
    with ThreadPoolExecutor(max_workers=workers) as executor:
        yield from executor.map(_scan_eml_path, arguments, chunksize=16)


def write_safe_metadata_jsonl(directory: Path, output: Path, *, workers: int = 1) -> dict[str, int]:
    """Stream privacy-safe scanner output to an ignored JSONL file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    scanned = parse_safe = rejected = 0
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            for row in scan_eml_directory(directory, workers=workers):
                handle.write(json.dumps(row, sort_keys=True) + "\n")
                scanned += 1
                if row.get("parse_safe") is True:
                    parse_safe += 1
                else:
                    rejected += 1
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"scanned": scanned, "parse_safe": parse_safe, "unsafe": rejected}


def build_source_inventory(records: Iterable[dict[str, Any]], *, source_commit_sha: str | None = None) -> dict[str, Any]:
    """Summarize privacy-safe metadata derived by a separate safe parser."""
    rows = list(records)
    exact = Counter(str(row.get("sha256") or "") for row in rows if row.get("sha256"))
    normalized = Counter(str(row.get("normalized_hash") or "") for row in rows if row.get("normalized_hash"))
    mime = Counter()
    languages = Counter()
    periods = Counter()
    campaigns = Counter()
    templates = Counter()
    privacy_flags = Counter()
    attachment_count = malformed_count = unsafe_count = privacy_review_count = 0
    for row in rows:
        _safe_identifier(row.get("candidate_id"), "candidate_id")
        languages[str(row.get("language") or "unknown").lower()] += 1
        periods[_safe_bucket(row.get("period_bucket"))] += 1
        attachment_count += max(0, int(row.get("attachment_count") or 0))
        malformed_count += int(bool(row.get("malformed")))
        unsafe_count += int(row.get("parse_safe") is False)
        privacy_review_count += int(bool(row.get("privacy_review_required")))
        privacy_flags.update(str(flag) for flag in row.get("privacy_flags") or [])
        for content_type in row.get("mime_types") or []:
            safe_type = str(content_type).lower().split(";", 1)[0].strip()
            if re.fullmatch(r"[a-z0-9.+_-]+/[a-z0-9.+_-]+", safe_type):
                mime[safe_type] += 1
        if row.get("campaign_group"):
            campaigns[_safe_identifier(row["campaign_group"], "campaign_group")] += 1
        if row.get("template_group"):
            templates[_safe_identifier(row["template_group"], "template_group")] += 1
    return {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "source_commit_sha": source_commit_sha,
        "total_eml_files": len(rows),
        "period_distribution": dict(sorted(periods.items())),
        "language_distribution": dict(sorted(languages.items())),
        "attachment_count": attachment_count,
        "mime_content_types": dict(sorted(mime.items())),
        "malformed_message_count": malformed_count,
        "unsafe_parse_count": unsafe_count,
        "privacy_review_required_count": privacy_review_count,
        "privacy_flag_category_counts": dict(sorted(privacy_flags.items())),
        "exact_duplicate_count": sum(count - 1 for count in exact.values() if count > 1),
        "raw_file_exact_duplicate_count": sum(count - 1 for count in exact.values() if count > 1),
        "normalized_duplicate_count": sum(count - 1 for count in normalized.values() if count > 1),
        "candidate_campaign_clusters": len(campaigns),
        "candidate_template_clusters": len(templates),
        "campaign_size_distribution": dict(sorted(Counter(campaigns.values()).items())),
        "template_size_distribution": dict(sorted(Counter(templates.values()).items())),
        "privacy_note": "Only aggregate metadata is included; addresses, URLs, bodies, and attachment content are excluded.",
    }


def inventory_markdown(report: dict[str, Any]) -> str:
    return "\n".join([
        "# Phishing Pot Source Inventory", "",
        f"- Repository-tree EML files: {report.get('repository_tree_eml_count', report['total_eml_files'])}",
        f"- Locally scanned EML records: {report['total_eml_files']}",
        f"- Checkout files unavailable to the safe parser: {report.get('local_checkout_unavailable_count', 0)}",
        f"- Language distribution: `{json.dumps(report['language_distribution'], sort_keys=True)}`",
        f"- MIME types: `{json.dumps(report['mime_content_types'], sort_keys=True)}`",
        f"- Attachments: {report['attachment_count']}",
        f"- Malformed: {report['malformed_message_count']}",
        f"- Unsafe/unparseable: {report['unsafe_parse_count']}",
        f"- Privacy review required: {report['privacy_review_required_count']}",
        f"- Privacy flag categories: `{json.dumps(report['privacy_flag_category_counts'], sort_keys=True)}`",
        f"- Exact duplicates: {report['exact_duplicate_count']}",
        f"- Normalized duplicates: {report['normalized_duplicate_count']}",
        f"- Campaign clusters: {report['candidate_campaign_clusters']}",
        f"- Template clusters: {report['candidate_template_clusters']}", "",
        report["privacy_note"], "",
    ])


def write_source_inventory(records: Iterable[dict[str, Any]], output_dir: Path, *, source_commit_sha: str | None = None) -> dict[str, Any]:
    report = build_source_inventory(records, source_commit_sha=source_commit_sha)
    _write_json(output_dir / "source_inventory.json", report)
    (output_dir / "source_inventory.md").write_text(inventory_markdown(report), encoding="utf-8")
    return report


def _selection_order(row: dict[str, Any], seed: str) -> tuple[bool, int, str]:
    evidence_score = sum(bool(row.get(key)) for key in ("has_header_evidence", "has_url_evidence", "has_authentication_evidence"))
    candidate_id = _safe_identifier(row.get("candidate_id"), "candidate_id")
    digest = hashlib.sha256(f"{seed}:{candidate_id}".encode("utf-8")).hexdigest()
    return row.get("brand_group") == "brand-unknown", -evidence_score, digest


def select_pilot_candidates(
    records: Iterable[dict[str, Any]], *, count: int = PLANNED_COUNT, seed: str = SELECTION_SEED,
) -> dict[str, Any]:
    """Select diverse provisional candidates from privacy-safe metadata."""
    if count != PLANNED_COUNT:
        raise ValueError(f"Phishing Pot pilot must select exactly {PLANNED_COUNT} candidates")
    eligible: list[dict[str, Any]] = []
    rejected = Counter()
    for row in records:
        _safe_identifier(row.get("candidate_id"), "candidate_id")
        reasons = []
        if str(row.get("language") or "").lower() != "en":
            reasons.append("non_english")
        if row.get("parse_safe") is not True or row.get("malformed") is True:
            reasons.append("unsafe_or_malformed")
        if row.get("phishing_intent") is not True:
            reasons.append("phishing_intent_unconfirmed")
        if row.get("privacy_unresolved") is True:
            reasons.append("privacy_unresolved")
        if row.get("boundary_overlap") is True:
            reasons.append("boundary_overlap")
        if row.get("boundary_overlap_status") != "compared_clear":
            reasons.append("boundary_overlap_incomplete")
        if row.get("internal_duplicate_status") != "clear":
            reasons.append("internal_duplicate_or_unchecked")
        if not row.get("campaign_group") or not row.get("template_group"):
            reasons.append("grouping_incomplete")
        if reasons:
            rejected.update(reasons)
        else:
            eligible.append(row)

    selected: list[dict[str, Any]] = []
    campaigns: Counter[str] = Counter()
    templates: Counter[str] = Counter()
    brands: Counter[str] = Counter()
    themes: Counter[str] = Counter()
    sender_infrastructure: Counter[str] = Counter()
    brand_limit = max(1, int(count * 0.25))
    seen_exact: set[str] = set()
    seen_normalized: set[str] = set()
    ordered = sorted(eligible, key=lambda item: _selection_order(item, seed))

    def consider(row: dict[str, Any], *, template_limit: int) -> bool:
        campaign = _safe_identifier(row["campaign_group"], "campaign_group")
        template = _safe_identifier(row["template_group"], "template_group")
        brand = _safe_identifier(row.get("brand_group") or "unknown", "brand_group")
        theme = _safe_identifier(row.get("theme_group") or "unknown", "theme_group")
        infrastructure = _safe_identifier(
            row.get("sender_infrastructure_group") or "unknown", "sender_infrastructure_group",
        )
        exact_hash = str(row.get("content_hash") or row.get("sha256") or "")
        normalized_hash = str(row.get("normalized_hash") or "")
        if (exact_hash and exact_hash in seen_exact) or (normalized_hash and normalized_hash in seen_normalized):
            rejected["duplicate"] += 1
            return False
        if campaigns[campaign] >= 2:
            return False
        if templates[template] >= template_limit:
            return False
        # "Unknown" is an absence of reliable brand evidence, not a brand that
        # may consume the 25% cap. Named/recognized brands remain capped.
        if brand != "brand-unknown" and brands[brand] >= brand_limit:
            return False
        candidate_id = _safe_identifier(row["candidate_id"], "candidate_id")
        selected.append({
            "candidate_id": candidate_id,
            "campaign_group": campaign,
            "template_group": template,
            "brand_group": brand,
            "theme_group": theme,
            "sender_infrastructure_group": infrastructure,
            "selection_reason": "English, parse-safe, provisionally phishing, privacy-clear metadata with permitted diversity limits",
            "review_status": "awaiting_manual_review",
        })
        campaigns[campaign] += 1
        templates[template] += 1
        brands[brand] += 1
        themes[theme] += 1
        sender_infrastructure[infrastructure] += 1
        if exact_hash:
            seen_exact.add(exact_hash)
        if normalized_hash:
            seen_normalized.add(normalized_hash)
        return True

    for row in ordered:
        consider(row, template_limit=1)
        if len(selected) == count:
            break
    template_relaxation_used = len(selected) < count
    if template_relaxation_used:
        for row in ordered:
            consider(row, template_limit=2)
            if len(selected) == count:
                break
    if len(selected) != count:
        raise ValueError(f"Could not select exactly {count} candidates under diversity and safety limits; selected {len(selected)}")
    return {
        "schema_version": 1, "pilot_id": PILOT_ID, "source_id": SOURCE_ID,
        "selection_seed": seed, "selection_algorithm": "evidence_score_then_seeded_sha256_v1",
        "template_limit_relaxation_used": template_relaxation_used,
        "selection_criteria": {
            "language": "en", "phishing_intent_required": True,
            "parse_safe_required": True, "privacy_clear_required": True,
            "boundary_overlap_allowed": False, "maximum_per_campaign": 2,
            "maximum_per_template": 2 if template_relaxation_used else 1,
            "template_limit_policy": "one unless fewer than 22 candidates can be selected, then at most two",
            "maximum_brand_fraction": 0.25,
        },
        "planned_count": count, "selected_count": len(selected),
        "selected_candidate_ids": [row["candidate_id"] for row in selected],
        "candidates": selected,
        "campaign_distribution": dict(sorted(campaigns.items())),
        "template_distribution": dict(sorted(templates.items())),
        "brand_distribution": dict(sorted(brands.items())),
        "unknown_brand_count": brands.get("brand-unknown", 0),
        "named_brand_max_count": max(
            (value for key, value in brands.items() if key != "brand-unknown"),
            default=0,
        ),
        "named_brand_max_fraction": round(
            max((value for key, value in brands.items() if key != "brand-unknown"), default=0) / count,
            6,
        ),
        "theme_distribution": dict(sorted(themes.items())),
        "sender_infrastructure_distribution": dict(sorted(sender_infrastructure.items())),
        "language_distribution": {"en": len(selected)},
        "excluded_reason_counts": dict(sorted(rejected.items())),
        "all_candidates_provisional": True,
        "promotion_eligible": False,
        "promotion_blockers": ["source_approval_incomplete", "sample_review_incomplete", "privacy_approval_incomplete"],
        "privacy_note": "Candidate IDs and grouping labels are opaque; no message content or sensitive values are included.",
    }


def selection_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phishing Pot Candidate Selection", "",
        f"- Selected: {report['selected_count']} of {report['planned_count']}",
        f"- Seed: `{report['selection_seed']}`",
        f"- Algorithm: `{report['selection_algorithm']}`",
        "- Status: all candidates await manual review",
        "- Promotion eligible: no", "", "## Candidate IDs", "",
    ]
    lines.extend(f"- `{candidate_id}`" for candidate_id in report["selected_candidate_ids"])
    lines.extend(["", report["privacy_note"], ""])
    return "\n".join(lines)


def write_candidate_selection(records: Iterable[dict[str, Any]], output_dir: Path, *, seed: str = SELECTION_SEED) -> dict[str, Any]:
    report = select_pilot_candidates(records, seed=seed)
    _write_json(output_dir / "candidate_selection.json", report)
    (output_dir / "candidate_selection.md").write_text(selection_markdown(report), encoding="utf-8")
    return report


def load_metadata_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load a metadata-only JSONL file, rejecting bodies and sensitive fields."""
    forbidden = {"text", "body", "html", "raw_email", "urls", "from", "to", "cc", "reply_to", "return_path"}
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        present = forbidden.intersection(key.lower() for key in row)
        if present:
            raise ValueError(f"Metadata row {number} contains forbidden content fields: {sorted(present)}")
        rows.append(row)
    return rows
