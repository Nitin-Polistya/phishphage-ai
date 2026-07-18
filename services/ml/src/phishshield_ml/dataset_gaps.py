"""Taxonomy validation and deterministic dataset gap analysis."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .corpus_inventory import ACTIVE_BOUNDARIES, load_boundary_records


REQUIRED_CATEGORY_FIELDS = {
    "id", "description", "target_minimum_real_samples", "desired_campaign_groups",
    "desired_source_diversity", "priority", "label", "allowed_uses", "known_leakage_risks",
}


def validate_taxonomy(taxonomy: dict[str, Any]) -> None:
    categories = taxonomy.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("Taxonomy must contain categories")
    identifiers: set[str] = set()
    for category in categories:
        missing = REQUIRED_CATEGORY_FIELDS - set(category)
        if missing:
            raise ValueError(f"Taxonomy category is missing fields: {sorted(missing)}")
        if category["id"] in identifiers:
            raise ValueError(f"Duplicate taxonomy id: {category['id']}")
        identifiers.add(category["id"])
        if category["label"] not in {0, 1}:
            raise ValueError(f"Invalid taxonomy label: {category['id']}")
        if not category["allowed_uses"]:
            raise ValueError(f"Category has no allowed uses: {category['id']}")


def validate_source_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "source_name", "source_type", "homepage_or_reference", "license", "label_mapping",
        "language_policy", "allowed_splits", "external_evaluation_only", "acquisition_method",
        "expected_format", "expected_categories", "required_provenance", "deduplication_policy",
        "privacy_policy", "enabled",
    }
    missing = required - set(manifest)
    if missing:
        raise ValueError(f"Source manifest is missing fields: {sorted(missing)}")
    license_status = manifest["license"].get("status")
    if manifest["license"].get("name") == "unknown" and license_status != "manual_review_required":
        raise ValueError("Unknown licenses require manual review")
    if license_status == "manual_review_required" and manifest["enabled"]:
        raise ValueError("A source awaiting license review cannot be enabled")


def _category_index(taxonomy: dict[str, Any]) -> dict[tuple[int, str], str]:
    aliases: dict[tuple[int, str], str] = {}
    for category in taxonomy["categories"]:
        for alias in category.get("aliases", []):
            key = (category["label"], str(alias).strip().lower())
            if key in aliases:
                raise ValueError(f"Duplicate alias for label {key[0]}: {key[1]}")
            aliases[key] = category["id"]
    return aliases


def build_gap_analysis(root: Path, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    taxonomy_path = root / "config/dataset_expansion_taxonomy.json"
    taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    validate_taxonomy(taxonomy)
    aliases = _category_index(taxonomy)
    # Gap planning uses only the active development pool. Diagnostics and external
    # benchmarks remain evaluation evidence, not acquisition-credit for training.
    records, _ = load_boundary_records(root, {"development_pool": ACTIVE_BOUNDARIES["development_pool"]})
    categorized: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unmapped = Counter()
    for record in records:
        message_type = str(record.get("message_type") or "unknown").lower()
        category_id = aliases.get((record["label"], message_type))
        if category_id:
            categorized[category_id].append(record)
        else:
            unmapped[f"{record['label']}:{message_type}"] += 1

    categories = []
    for category in taxonomy["categories"]:
        rows = categorized[category["id"]]
        real_rows = [row for row in rows if row["is_synthetic"] is False]
        synthetic_rows = [row for row in rows if row["is_synthetic"] is True]
        campaigns = {row["campaign_group"] for row in rows if row["campaign_group"]}
        sources = Counter(row["source_name"] for row in rows)
        templates = Counter(row["template_group"] for row in rows if row["template_group"])
        brands = Counter(row["brand_family"] for row in rows if row["brand_family"])
        providers = Counter(row["delivery_provider"] for row in rows if row["delivery_provider"])
        normalized = Counter(row["normalized_content_hash"] for row in rows)
        target = int(category["target_minimum_real_samples"])
        sample_deficit = max(0, target - len(real_rows))
        campaign_deficit = max(0, int(category["desired_campaign_groups"]) - len(campaigns))
        source_deficit = max(0, int(category["desired_source_diversity"]) - len(sources))
        domination: list[str] = []

        def dominant(counter: Counter, name: str) -> None:
            if rows and counter:
                value, count = counter.most_common(1)[0]
                if count / len(rows) > 0.60:
                    domination.append(f"one_{name}:{value}:{count / len(rows):.1%}")

        dominant(sources, "source")
        dominant(templates, "template")
        dominant(Counter(row["campaign_group"] for row in rows if row["campaign_group"]), "campaign")
        dominant(brands, "brand")
        dominant(providers, "delivery_provider")
        if rows and len(synthetic_rows) / len(rows) > 0.40:
            domination.append(f"synthetic:{len(synthetic_rows) / len(rows):.1%}")
        if rows and sum(count - 1 for count in normalized.values()) / len(rows) > 0.20:
            domination.append("repeated_vocabulary_or_normalized_template")
        priority_score = int(category["priority"]) * (sample_deficit + 20 * campaign_deficit + 10 * source_deficit)
        action = (
            f"Acquire {min(sample_deficit, 50)} independently licensed real English samples "
            f"from at least {max(1, source_deficit)} new source(s), grouped into "
            f"at least {max(1, campaign_deficit)} independent campaign(s); review privacy and license before ingestion."
            if sample_deficit else "No count addition is currently required; continue campaign and source diversity review."
        )
        categories.append({
            "category_id": category["id"], "label": category["label"], "priority": category["priority"],
            "current_sample_count": len(rows), "current_real_sample_count": len(real_rows),
            "synthetic_count": len(synthetic_rows), "independent_campaign_count": len(campaigns),
            "distinct_source_count": len(sources), "target_real_sample_count": target,
            "sample_deficit": sample_deficit, "campaign_deficit": campaign_deficit,
            "source_diversity_deficit": source_deficit, "priority_score": priority_score,
            "leakage_risk": category["known_leakage_risks"], "dominance_warnings": domination,
            "recommended_acquisition_action": action,
        })
    ranked = sorted(categories, key=lambda item: (-item["priority_score"], item["category_id"]))
    return {
        "schema_version": 1, "deterministic": True,
        "planning_boundary": "development_pool only; external and diagnostic data receive no training-coverage credit",
        "development_rows": len(records), "categorized_rows": sum(len(rows) for rows in categorized.values()),
        "unmapped_message_types": dict(sorted(unmapped.items())),
        "categories": sorted(categories, key=lambda item: item["category_id"]),
        "smallest_high_value_additions_first": [item["category_id"] for item in ranked[:10]],
        "quality_warning": "Corpus size alone does not prove quality. License, privacy, independent campaigns, source diversity, and leakage controls remain mandatory.",
    }


def gap_markdown(analysis: dict[str, Any]) -> str:
    lines = ["# Dataset Gap Analysis", "", analysis["planning_boundary"], "", f"Development rows: {analysis['development_rows']}; taxonomy-attributed rows: {analysis['categorized_rows']}.", "", "## Highest-value gaps", "", "| Category | Real | Synthetic | Campaigns | Sources | Real target | Deficit | Warnings |", "|---|---:|---:|---:|---:|---:|---:|---|"]
    by_id = {item["category_id"]: item for item in analysis["categories"]}
    for identifier in analysis["smallest_high_value_additions_first"]:
        item = by_id[identifier]
        lines.append(f"| {identifier} | {item['current_real_sample_count']} | {item['synthetic_count']} | {item['independent_campaign_count']} | {item['distinct_source_count']} | {item['target_real_sample_count']} | {item['sample_deficit']} | {', '.join(item['dominance_warnings']) or 'none'} |")
    lines.extend(["", "## Attribution limits", "", f"Unmapped message types: `{json.dumps(analysis['unmapped_message_types'], sort_keys=True)}`", "", analysis["quality_warning"], "", "The JSON report contains every category, deficit, leakage risk, and recommended action.", ""])
    return "\n".join(lines)


def write_gap_analysis(root: Path, json_output: Path, markdown_output: Path) -> dict[str, Any]:
    analysis = build_gap_analysis(root)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_output.write_text(gap_markdown(analysis), encoding="utf-8")
    return analysis
