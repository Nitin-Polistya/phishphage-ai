# Portfolio asset library

This directory contains privacy-reviewed source material for the PhishShield AI portfolio presentation. It is intentionally organized so that generated assets and manual captures remain separate from application code.

| Directory | Purpose |
| --- | --- |
| [`screenshots/`](screenshots/) | Reviewed browser captures. Empty until a human capture pass is completed. |
| [`diagrams/`](diagrams/) | Mermaid source for system, request, model, safety, deployment, and observability diagrams. |
| [`social/`](social/) | GitHub/social preview specification and SVG-safe source. |
| [`demo/`](demo/) | Fully synthetic `.eml` fixtures and expected behavior for demonstrations. |

Portfolio assets must use synthetic data, avoid active destinations, and pass the privacy checklist in [`docs/PORTFOLIO_ASSET_CHECKLIST.md`](../PORTFOLIO_ASSET_CHECKLIST.md). Do not place private model artifacts, raw mailbox exports, secrets, or unreviewed screenshots here.

## Capture status

The repository contains source specifications and placeholders only. Screenshots and video are manual deliverables; no browser recording or binary image generation was performed in this phase.
