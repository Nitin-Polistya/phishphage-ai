"""Check relative Markdown links and practical heading anchors without dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "node_modules", ".next", "__pycache__"}
LINK_RE = re.compile(r"!?(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")


def slug(text: str) -> str:
    text = re.sub(r"[`*_~]", "", text).lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text).strip("-")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in SKIP_PARTS for part in path.parts)
    )


def main() -> int:
    issues: list[str] = []
    checked = 0
    for source in markdown_files():
        text = source.read_text(encoding="utf-8", errors="replace")
        headings = {slug(match.group(1)) for line in text.splitlines() if (match := HEADING_RE.match(line))}
        for raw_target in LINK_RE.findall(text):
            target = raw_target.strip().strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            checked += 1
            path_part = unquote(parsed.path)
            if path_part:
                target_path = (source.parent / path_part).resolve()
                if not target_path.exists():
                    issues.append(f"{source.relative_to(ROOT)} -> {target}")
                    continue
                if parsed.fragment and target_path.suffix.lower() == ".md":
                    target_text = target_path.read_text(encoding="utf-8", errors="replace")
                    target_headings = {
                        slug(match.group(1))
                        for line in target_text.splitlines()
                        if (match := HEADING_RE.match(line))
                    }
                    if slug(parsed.fragment) not in target_headings:
                        issues.append(f"{source.relative_to(ROOT)} -> {target}")
            elif parsed.fragment and slug(parsed.fragment) not in headings:
                issues.append(f"{source.relative_to(ROOT)} -> {target}")

    print(f"checked_relative_links={checked}")
    print(f"broken_links={len(issues)}")
    for issue in issues:
        print(issue)
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
