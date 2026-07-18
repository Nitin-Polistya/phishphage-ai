"""Generate deterministic corpus inventory reports without modifying datasets."""

from __future__ import annotations

import argparse
from pathlib import Path

from phishshield_ml.corpus_inventory import write_inventory


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path, default=root / "reports/corpus_inventory.json")
    parser.add_argument("--markdown-output", type=Path, default=root / "reports/corpus_inventory.md")
    parser.add_argument("--no-strict", action="store_true", help="Write violations to the report without returning an error")
    args = parser.parse_args()
    inventory = write_inventory(root, args.json_output, args.markdown_output, strict=not args.no_strict)
    print(f"Audited {inventory['total_rows']} configured rows.")


if __name__ == "__main__":
    main()
