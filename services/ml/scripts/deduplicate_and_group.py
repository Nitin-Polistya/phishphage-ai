"""Remove duplicate templates and create leakage-resistant grouped splits."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.acquisition import assert_not_external_path, read_jsonl
from phishshield_ml.dataset import canonicalize_template, split_dataset
from phishshield_ml.preprocessing import normalize_email_text


TOKEN_PATTERN = re.compile(r"[a-z0-9_<>{}-]+")


def simhash64(text: str) -> int:
    tokens = TOKEN_PATTERN.findall(canonicalize_template(text))
    shingles = [" ".join(tokens[index:index + 3]) for index in range(max(1, len(tokens) - 2))]
    if not shingles:
        shingles = [canonicalize_template(text)]
    vector = [0] * 64
    for shingle in shingles:
        value = int.from_bytes(hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    return sum((1 << bit) for bit, weight in enumerate(vector) if weight >= 0)


def hamming_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def deduplicate(rows: list[dict], max_hamming: int = 3) -> tuple[list[dict], dict]:
    exact_seen: set[str] = set()
    canonical_seen: set[str] = set()
    band_index: dict[tuple[int, int, int], list[tuple[int, int]]] = defaultdict(list)
    kept: list[dict] = []
    counters = Counter()

    for row in rows:
        text = normalize_email_text(row.get("text", ""))
        if not text:
            counters["empty"] += 1
            continue
        exact = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if exact in exact_seen:
            counters["exact_duplicate"] += 1
            continue
        exact_seen.add(exact)
        canonical = canonicalize_template(text)
        canonical_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if canonical_hash in canonical_seen:
            counters["canonical_template_duplicate"] += 1
            continue
        fingerprint = simhash64(text)
        label = int(row["label"])
        candidate_indices: set[int] = set()
        for band in range(4):
            key = (label, band, (fingerprint >> (band * 16)) & 0xFFFF)
            candidate_indices.update(index for _, index in band_index[key])
        if any(hamming_distance(fingerprint, kept[index]["_simhash"]) <= max_hamming for index in candidate_indices):
            counters["fuzzy_template_duplicate"] += 1
            continue

        canonical_seen.add(canonical_hash)
        campaign = str(row.get("campaign_id") or "unknown")
        if campaign.endswith(":unassigned"):
            campaign = f"{row['source']}:template:{canonical_hash[:16]}"
        prepared = {
            **row,
            "text": text,
            "text_sha256": exact,
            "template_hash": canonical_hash,
            "campaign_id": campaign,
            "_simhash": fingerprint,
        }
        # Near-identical templates have already been removed globally. Group all
        # remaining messages from the same source campaign together so a campaign
        # cannot cross folds; template_hash remains available for the audit.
        prepared["template_group"] = hashlib.sha256(
            f"{prepared['source']}|{campaign}".encode("utf-8")
        ).hexdigest()[:20]
        index = len(kept)
        kept.append(prepared)
        for band in range(4):
            key = (label, band, (fingerprint >> (band * 16)) & 0xFFFF)
            band_index[key].append((fingerprint, index))

    for row in kept:
        row.pop("_simhash", None)
    return kept, dict(counters)


def _safe_csv(frame: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        column for column in (
            "text", "label", "source", "source_role", "campaign_id", "template_group",
            "language", "language_confidence", "text_sha256", "template_hash",
        ) if column in frame.columns
    ]
    frame[columns].to_csv(path, index=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=ROOT / "data" / "interim" / "english_candidates.jsonl", type=Path)
    parser.add_argument("--output-root", default=ROOT / "data" / "processed" / "english_core", type=Path)
    parser.add_argument("--report", default=ROOT / "data" / "interim" / "deduplication_and_split_audit.json", type=Path)
    parser.add_argument("--max-simhash-distance", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    assert_not_external_path(args.input)
    rows = read_jsonl(args.input) if args.input.exists() else []
    before_counts = Counter(int(row["label"]) for row in rows)
    clean, removed = deduplicate(rows, max_hamming=args.max_simhash_distance)
    frame = pd.DataFrame(clean)
    after_counts = Counter(int(row["label"]) for row in clean)
    status = "review_required"
    split_summary = None
    reason = "Source audit and corpus statistics must be reviewed before training"

    args.output_root.mkdir(parents=True, exist_ok=True)
    _safe_csv(frame, args.output_root / "review_corpus.csv")
    if len(frame) >= 20 and frame["label"].nunique() == 2 and frame["template_group"].nunique() >= 5:
        try:
            train, validation, test, summary = split_dataset(frame, random_state=args.seed)
            _safe_csv(train, args.output_root / "train.csv")
            _safe_csv(validation, args.output_root / "validation.csv")
            _safe_csv(test, args.output_root / "test.csv")
            status = "splits_created_review_required"
            split_summary = {
                "train": summary.train_rows,
                "validation": summary.validation_rows,
                "test": summary.test_rows,
            }
            reason = "Splits are staged but are not authorized for training until review"
        except ValueError as exc:
            reason = f"Split blocked: {exc}"
    else:
        reason = "Split blocked: the approved corpus does not yet contain both classes and sufficient groups"

    report = {
        "schema_version": 1,
        "input_rows": len(rows),
        "class_counts_before_cleaning": {"legitimate": before_counts[0], "phishing": before_counts[1]},
        "rows_after_cleaning": len(clean),
        "class_counts_after_cleaning": {"legitimate": after_counts[0], "phishing": after_counts[1]},
        "removed": removed,
        "template_groups": int(frame["template_group"].nunique()) if not frame.empty else 0,
        "split_strategy": "deterministic StratifiedGroupKFold, seed 42; exact and near-template duplicates removed globally, then source/campaign groups kept intact",
        "split_summary": split_summary,
        "status": status,
        "ready_for_training": False,
        "reason": reason,
        "external_validation_read": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
