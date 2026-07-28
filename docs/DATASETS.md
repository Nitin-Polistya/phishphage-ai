# Dataset and provenance notes

This document describes dataset boundaries and evidence currently present in the repository. Raw email, raw `.eml` files, and private staging material are not redistributed by this documentation. Dataset availability or a public download page does not by itself mean that the project may train on or redistribute the content.

## Inventory and roles

| Source or boundary | Current role | Language | Evidence/status |
| --- | --- | --- | --- |
| Zenodo phishing/social-engineering corpus | Core phishing-positive development source; only explicit `Phishing` labels are accepted | Declared English; per-row audit required | Approved for the configured development role, but source-dominant. Current inventory attributes 285 rows. |
| Project-authored synthetic corpus and targeted anchors | Historical scenario coverage and training-only anchors | English | Existing project artifacts; synthetic and license status remain separate governance concerns. Not a new acquisition. |
| Zenodo phishing validation emails | External development/validation boundary | Declared English | CC BY 4.0 record; external-only and duplication-limited. Current boundary is 100 rows. It is not a training source. |
| Contextual Email Deception Detection benchmark | Final external benchmark | English | Current inventory has 80 rows and 50/50 class balance. The controlled source registry keeps its provenance/license reconciliation pending and external-only. |
| SpaPhish | Independent diagnostic/qualification source and future Spanish supplement | Spanish | Repository record shows CC BY 4.0, but stable unauthenticated acquisition and privacy review are unresolved. It is not part of the primary English training pool. |
| PhishingPot metadata and staged pilot | Research-only candidate for campaign/infrastructure coverage | Primarily English candidate; must be audited | CC BY-NC 4.0 restricted non-commercial research; sample privacy/label review is pending, raw redistribution disabled, no promotion allowed. |
| CMU Enron | Proposed legitimate workplace source | Primarily English | Blocked: official page does not state a reusable content license and messages are privacy-sensitive. |
| SpamAssassin `easy_ham` | Proposed legitimate source | Mixed/unspecified | Blocked: original message copyright remains with senders; no dataset-wide reuse license. |
| SpamAssassin `hard_ham` | Proposed legitimate hard-negative source | Mixed/unspecified | Blocked for the same licensing/privacy reason; useful conceptually but not ingested. |
| SpamAssassin `spam` | Generic spam hard-negative concept | Mixed/unspecified | Blocked and never silently mapped to phishing. Spam and phishing are separate labels. |
| PhishTank/OpenPhish metadata | URL reputation only | Not applicable | Excluded from email-body labels. A reported URL is not an email label. |

The configured corpus audit reports 656 rows across boundaries: 298 development-pool rows, 100 external-development rows, 80 final-external rows, and 178 grouped-diagnostic rows. The 298-row development pool has 193 legitimate and 105 phishing rows across 271 campaign groups; the source-dominance audit attributes 77.9% of that pool to one Zenodo source. Historical narrative files contain older pre-cleaning counts; use the generated audit reports for the boundary-specific current counts.

## Intended use of each boundary

- Training/development: the 298-row English development pool is the controlled development boundary for the current research artifact. It is small, source-dominant, and contains synthetic material.
- Validation/model selection: fixed and grouped validation manifests are used for controlled candidate selection and threshold review. They are not interchangeable with external evaluation.
- External evaluation: the 100-row Zenodo validation boundary and 80-row final benchmark are kept outside training. The 80-row benchmark was evaluated after model lock and used for evidence, not selection.
- Diagnostic-only: grouped/template-shift sets, hard-negative fixtures, false-negative challenge sets, candidate qualification sources, PhishingPot pilots, feature ablations, and source-separability experiments are diagnostic or research boundaries. Their results do not authorize activation.

## Language coverage

The primary development workflow is English-first. The corpus audit records 655 English rows and one `ca` language estimate across its configured combined boundaries; language detectors are estimates, not ground truth. SpaPhish is Spanish and remains outside the primary English model. Multilingual performance is therefore unqualified.

## Label provenance

The binary positive class is explicit phishing only. Generic spam, malware, scareware, baiting, pretexting, and other social-engineering categories are not silently converted to phishing. Source labels are retained with source IDs and split roles. External sources are physically/logically isolated from training and threshold selection where the manifests require it.

## Privacy handling

- Do not add real personal email to the repository, issue tracker, public reports, or screenshots.
- Prefer aggregate counts, hashes, and provenance metadata over message text.
- Never export full addresses, Message-IDs, Received chains, URLs with identifiers, attachment bytes, or unsanitized headers to generated reports.
- Do not render HTML, fetch links, execute attachments, or decode untrusted payloads merely to classify a source.
- PhishingPot staging is ignored and restricted to manual privacy/label review; no raw sample may be committed or redistributed.
- Dataset license, privacy approval, and redistribution rights are separate gates.

## Deduplication and campaign grouping

The development controls normalize Unicode/whitespace, reject exact duplicates, track normalized duplicates, group near-duplicates, and keep campaign/template groups within one split. The current corpus inventory reports zero exact duplicate rows in its configured boundaries, while 127 normalized and 131 semantic near-duplicate relationships remain recorded as audit warnings. The internal grouped diagnostic is selection-aware and must not be described as an untouched test set.

Campaign grouping is uneven. The development pool has 271 groups for 298 rows, but source fields differ substantially. PhishingPot has richer campaign/infrastructure metadata; the core source has sparse sender, organization, country, URL, and attachment metadata. SpaPhish has limited canonical campaign/country metadata.

## Known biases and coverage gaps

- English and synthetic/template language is overrepresented.
- A single Zenodo source dominates the development pool.
- The external benchmark is small, balanced, and synthetic/templated relative to a real inbox.
- Real workplace, banking, billing, support, collaboration, and account-notification hard negatives are scarce.
- Coverage is weak or unmeasurable for Microsoft 365, Google Workspace, OAuth consent, MFA bypass, QR phishing, Teams, Slack, Discord, AI/deepfake lures, modern crypto scams, and cloud-storage abuse.
- Country, provider, sender/infrastructure, attachment, time, and campaign fields are inconsistent.
- The hard-negative inventory is mostly fixtures and benchmark examples, not a balanced provider/workflow challenge set.
- Short, image-only, multilingual, compromised-account, and low-lexical-overlap messages are underrepresented.

These gaps explain why fixed validation can overstate performance and why false-negative and false-positive findings should be treated as evidence of limitations rather than accuracy claims.

## Hard-negative limitations

SpamAssassin `hard_ham` is a useful future concept but is blocked by licensing/privacy review. Current fixtures cover selected legitimate HTML/provider-like messages and a small hard-negative set. They do not represent all legitimate security alerts, invoices, password resets, SaaS notifications, newsletters, or workplace communication. A “safe” result on a hard negative is not a general false-positive guarantee.

## Modern phishing gaps

The current data does not establish coverage for live sender compromise, OAuth consent flows, QR codes, cloud-storage abuse, collaboration platforms, MFA fatigue, deepfake/AI lures, or current payment/crypto campaigns. URLs and metadata can be present without being safe labels, and PhishTank/OpenPhish feeds cannot repair this gap because they are URL reputation sources rather than email-body datasets.

## Dataset evolution roadmap

1. Approve only legally reusable, privacy-reviewed sources with row-level provenance.
2. Add real or carefully reviewed legitimate hard negatives matched to modern provider workflows.
3. Add modern phishing families across SaaS, OAuth, MFA, QR, collaboration, cloud storage, banking, invoice, and crypto scenarios.
4. Require language, campaign, template, provider, organization, country/proxy, sender/infrastructure, URL, and attachment metadata where lawful.
5. Split by campaign/template and preserve a time-based or source-independent external holdout.
6. Re-run deduplication, calibration, false-negative/false-positive analysis, and candidate gates before any model promotion.

No acquisition, dataset modification, retraining, label change, threshold change, or model promotion occurred in this documentation phase.
