"""Run the registered deployment-candidate model on approved gold records only."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = ROOT / "services" / "ml" / "src"
API_ROOT = ROOT / "apps" / "api"
for path in (SRC_DIR, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.core.settings import get_settings  # noqa: E402
from app.services.model_manager import ModelManager  # noqa: E402
from phishshield_ml.gold_dataset_evaluation import (  # noqa: E402
    EVALUATION_SCRIPT_VERSION,
    adapt_approved_gold_dataset,
    build_evaluation_report,
    privacy_safe_artifact_text,
)


DEFAULT_DATASET = ROOT / "services/ml/evaluation/private/gold_dataset_reports/gold_dataset_v1.jsonl"
DEFAULT_REVIEW_DB = ROOT / "services/ml/evaluation/private/review_workspace.sqlite3"
DEFAULT_OUTPUT = ROOT / "services/ml/evaluation/private/gold_dataset_evaluation"
PRIVATE_ROOT = (ROOT / "services/ml/evaluation/private").resolve()


def _logical_path(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")


def _private_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError:
        raise ValueError("Evaluation inputs and outputs must remain under private evaluation storage.") from None
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if not privacy_safe_artifact_text(text):
        raise RuntimeError("Refusing to write a privacy-unsafe evaluation artifact.")
    path.write_text(text, encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, sort_keys=True, allow_nan=False) + "\n" for row in rows)
    if not privacy_safe_artifact_text(text):
        raise RuntimeError("Refusing to write a privacy-unsafe misclassification artifact.")
    path.write_text(text, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--review-db", type=Path, default=DEFAULT_REVIEW_DB)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-id", default=None, help="Optional registry model ID; default uses the API setting.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dataset_path = _private_path(args.dataset)
    review_db_path = _private_path(args.review_db)
    output_dir = _private_path(args.output_dir)
    if not dataset_path.is_file() or not review_db_path.is_file():
        raise FileNotFoundError("The approved gold export or private review store is missing.")

    records = adapt_approved_gold_dataset(dataset_path, review_db_path)
    if not records:
        raise RuntimeError("No approved gold records were adapted.")

    settings = get_settings()
    manager = ModelManager(
        registry_path=settings.ml_registry_path,
        selected_model_id=args.model_id or settings.ml_model_id,
        artifact_override=settings.ml_artifact_path,
    )
    loaded = manager.load_deployment_candidate()
    probabilities = [float(row[1]) for row in loaded.predictor.predict_proba([record.text for record in records])]
    report = build_evaluation_report(records, probabilities, loaded.record.threshold)
    timestamp = datetime.now(timezone.utc).isoformat()
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_hash = _sha256(dataset_path)
    output_manifest = {
        "status": "complete",
        "evaluation_script_version": EVALUATION_SCRIPT_VERSION,
        "evaluation_timestamp": timestamp,
        "dataset_path": _logical_path(dataset_path),
        "dataset_sha256": dataset_hash,
        "review_store": _logical_path(review_db_path),
        "adapter": {
            "input_schema": ["text", "label"],
            "approved_only": True,
            "content_join": "approved review ID to sanitized subject/body previews",
            "raw_content_persisted": False,
            "adapted_sample_count": len(records),
            "label_mapping": {"safe": 0, "phishing": 1},
            "stable_ordering": "source_sample_id_digest, sample_hash",
            "duplicate_hashes_rejected": True,
        },
        "model": {
            "model_id": loaded.record.model_id,
            "model_version": loaded.record.version,
            "model_artifact_sha256": loaded.record.sha256,
            "threshold": loaded.record.threshold,
            "calibration": loaded.record.calibration,
            "deployment_candidate": loaded.record.deployment_candidate,
            "activated": loaded.record.activated,
        },
        "output_directory": _logical_path(output_dir),
        "privacy": {
            "raw_private_content_emitted": False,
            "raw_headers_emitted": False,
            "email_addresses_emitted": False,
            "full_urls_emitted": False,
            "query_strings_emitted": False,
            "attachment_contents_emitted": False,
            "secret_values_emitted": False,
            "absolute_paths_emitted": False,
            "misclassification_identifiers": "privacy-safe source sample ID digests only",
        },
    }
    summary = {
        "evaluation_script_version": EVALUATION_SCRIPT_VERSION,
        "evaluation_timestamp": timestamp,
        "dataset_path": _logical_path(dataset_path),
        "dataset_sha256": dataset_hash,
        "model_id": loaded.record.model_id,
        "model_version": loaded.record.version,
        "model_artifact_sha256": loaded.record.sha256,
        "threshold": loaded.record.threshold,
        "calibration": loaded.record.calibration,
        "output_directory": _logical_path(output_dir),
        **{key: value for key, value in report.items() if key not in {"misclassifications", "per_source_results", "probability_summaries"}},
    }
    _write_json(output_dir / "evaluation_summary.json", summary)
    _write_json(output_dir / "probability_summaries.json", report["probability_summaries"])
    _write_json(output_dir / "per_source_results.json", {"sources": report["per_source_results"]})
    _write_json(output_dir / "evaluation_manifest.json", output_manifest)
    _write_jsonl(output_dir / "misclassification_report.jsonl", report["misclassifications"])

    print(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
