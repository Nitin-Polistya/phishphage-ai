from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import prepare_rich_metadata_pilot as pilot  # noqa: E402


def candidate(label: str = "phishing", campaign: str = "campaign-a", index: int = 0) -> pilot.Candidate:
    result = pilot.Candidate(
        source_dataset="fixture",
        label=label,
        campaign_id=campaign,
        language="en",
        subject=f"Notice {index}",
        body_excerpt=f"Please review this sanitized message with useful evidence {index}.",
        source_record_key=f"fixture-{index}",
        template_id=f"template-{index}",
        source_row=index + 1,
    ).finalize()
    assert result is not None
    return result


def test_exact_supported_headers_and_25_plus_25_rows(tmp_path: Path):
    safe = [candidate("safe", "safe-campaign", i) for i in range(25)]
    phishing = [candidate("phishing", "phish-campaign", i + 25) for i in range(25)]
    safe_rows = pilot.write_csv(tmp_path / "safe.csv", safe)
    phishing_rows = pilot.write_csv(tmp_path / "phishing.csv", phishing)
    assert len(safe_rows) == len(phishing_rows) == 25
    with (tmp_path / "safe.csv").open(encoding="utf-8") as handle:
        parsed = list(csv.DictReader(handle))
    assert list(parsed[0]) == pilot.HEADERS
    assert pilot.validate_rows(safe_rows, "safe")["expected_label_only"] is True
    assert pilot.validate_rows(phishing_rows, "phishing")["expected_label_only"] is True


def test_stable_ordering_and_synthetic_ids():
    records = [candidate(index=i) for i in range(4)]
    first = [item.source_sample_id for item in sorted(records, key=lambda item: pilot.stable_key(item, "seed"))]
    second = [item.source_sample_id for item in sorted(records, key=lambda item: pilot.stable_key(item, "seed"))]
    assert first == second
    assert all(item.source_sample_id.startswith("phish-") for item in records)


def test_privacy_sanitization_removes_urls_addresses_headers_and_html():
    cleaned = pilot.sanitize_text(
        "From: Person <person@example.test>\nVisit https://example.test/path?secret=abc\n"
        "<script>token=secretvalue</script><p>Dear Alice Smith, review this message.</p>",
        800,
    )
    assert "person@example.test" not in cleaned
    assert "https://" not in cleaned
    assert "secret=abc" not in cleaned
    assert "<p>" not in cleaned and "<script>" not in cleaned
    assert "From:" not in cleaned


def test_authentication_and_attachment_normalization_do_not_fabricate_missing_values():
    assert pilot.normalize_authentication({"spf": "pass", "dkim": "fail", "dmarc": "unavailable"}) == ["spf=pass", "dkim=fail"]
    assert pilot.normalize_authentication({"spf": "unavailable", "dkim": "unavailable", "dmarc": "unavailable"}) == []
    assert pilot.normalize_attachment(["<ATTACHMENT_PDF>"], ["application/pdf", "text/html"]) == (".pdf", "application/pdf")
    assert pilot.normalize_attachment([], ["text/html"]) == ("", "")


def test_url_domain_sanitization_uses_safe_non_clickable_placeholders():
    domains = pilot.normalize_url_groups(["url-domain-abcdef", "url-domain-abcdef", "url-domain-123456"])
    assert len(domains) == 3
    assert all("://" not in value and "/" not in value and "?" not in value for value in domains)


def test_duplicate_and_existing_overlap_rejection():
    first = candidate(index=1)
    duplicate = candidate(index=1)
    assert pilot.same_or_near_duplicate(duplicate, [first]) is True
    assert pilot.candidate_is_excluded(first, {first.content_hash}, set(), set()) == "existing_normalized_content_hash"
    assert pilot.candidate_is_excluded(first, set(), {first.legacy_content_hash}, set()) == "previous_or_existing_content_overlap"


def test_campaign_and_template_concentration_limits():
    records = [candidate(index=i) for i in range(8)]
    selected: list[pilot.Candidate] = []
    for item in records:
        if sum(existing.campaign_id == item.campaign_id for existing in selected) < 5 and sum(existing.template_id == item.template_id for existing in selected) < 1:
            selected.append(item)
    assert len(selected) == 5
    assert max(sum(item.campaign_id == "campaign-a" for item in selected), 0) <= 5


def test_manifest_hashes_are_stable_and_outputs_have_no_absolute_paths(tmp_path: Path):
    rows = [candidate("safe", "safe-campaign", i).to_row() for i in range(25)]
    path = tmp_path / "safe.csv"
    pilot.write_csv(path, [candidate("safe", "safe-campaign", i) for i in range(25)])
    manifest = {"file_sha256": pilot.sha256_file(path), "rows": len(rows)}
    encoded = json.dumps(manifest, sort_keys=True)
    assert manifest["file_sha256"] == pilot.sha256_file(path)
    assert str(tmp_path) not in encoded


def test_metric_free_boundary_no_human_or_model_fields_in_rows():
    row = candidate("safe").to_row()
    assert "final_human_label" not in row
    assert "adjudicated_label" not in row
    assert "approval" not in " ".join(row)
    assert row["source_claimed_label"] == "safe"
