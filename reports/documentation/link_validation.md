# Documentation link validation

Validation is performed by the dependency-free checker `scripts/check_docs_links.py`. It scans Markdown under the repository, skips external URLs, resolves relative targets case-sensitively where the host permits, and checks practical Markdown heading anchors.

Final result: `checked_relative_links=63`, `broken_links=0`, exit code 0. The repository's relative Markdown targets and practical heading anchors passed.

The checker does not validate external websites, image pixels, provider routes, or browser behavior.
