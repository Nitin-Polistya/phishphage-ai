"""Download only license-approved official dataset files from the registry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.acquisition import download_source, load_source_registry, validate_download_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=ROOT / "dataset_sources.json", type=Path)
    parser.add_argument("--raw-root", default=ROOT / "data" / "raw", type=Path)
    parser.add_argument("--external-root", default=ROOT / "data" / "external", type=Path)
    parser.add_argument("--manifest", default=ROOT / "data" / "interim" / "download_manifest.json", type=Path)
    parser.add_argument("--source", action="append", help="Download only this source id; repeat as needed")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    registry, sources = load_source_registry(args.registry)
    requested = args.source or [source.id for source in sources.values() if source.status == "approved"]
    unknown = sorted(set(requested) - set(sources))
    if unknown:
        raise SystemExit(f"Unknown source ids: {unknown}")

    records: list[dict] = []
    failures: list[dict] = []
    for source_id in requested:
        source = sources[source_id]
        try:
            validate_download_source(source)
            destination = args.external_root if source.role == "external_validation_only" else args.raw_root
            if args.dry_run:
                records.append({
                    "source_id": source.id,
                    "download_url": source.download_url,
                    "archive_filename": source.archive_filename,
                    "destination": str(destination),
                    "role": source.role,
                    "outcome": "dry_run_approved",
                })
            else:
                records.append(download_source(source, destination, overwrite=args.overwrite))
        except (PermissionError, ValueError, RuntimeError, OSError) as exc:
            failures.append({"source_id": source.id, "status": source.status, "reason": str(exc)})

    manifest = {
        "schema_version": 1,
        "registry_audited_on": registry["audited_on"],
        "dry_run": args.dry_run,
        "downloads": records,
        "blocked_or_failed": failures,
        "safety_policy": registry["safety_policy"],
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
