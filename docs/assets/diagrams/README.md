# Diagram sources

These Mermaid files are the source of truth for portfolio diagrams. Render them with a Mermaid-capable Markdown viewer or a reviewed local export process. They deliberately label Firebase as optional and keep private artifact provisioning and observability separate from user email processing.

| Source | Use | Accessibility description |
| --- | --- | --- |
| `system-architecture.mmd` | README and portfolio overview | A browser sends an email to FastAPI; parsing, rules, optional ML, and safety fusion return structured evidence. History stays in browser storage. |
| `analysis-request-flow.mmd` | Request-flow slide | Input is bounded, parsed in memory, analyzed, fused, and returned with privacy-safe logging. |
| `model-artifact-loading.mmd` | Model-integrity explanation | Registry metadata selects a candidate; hashes and manifests are verified before loading. |
| `decision-safety-fusion.mmd` | Decision-safety slide | Raw ML and rule evidence remain visible; independent deterministic evidence can prevent an unjustified safe presentation. |
| `deployment-topology.mmd` | Future topology | Managed frontend and FastAPI service are connected through HTTPS; model provisioning is private and Firebase is optional. |
| `observability-flow.mmd` | Operations slide | Health, readiness, metrics, and structured logs expose status without email content. |

Every exported diagram should retain a visible text caption or an adjacent description. Color is supplemental; labels and arrows carry the meaning.
