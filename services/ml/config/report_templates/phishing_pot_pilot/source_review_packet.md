# rf-peixoto Phishing Pot — source-review packet

Status: **pending sample-level review; not approved for acquisition or ingestion**

This packet records the questions that must be answered before any separately
authorised, non-commercial research staging review. It is metadata only and
contains no cloned repository content, EML files, URLs, or message bodies.

## Source and rights

- Official repository: <https://github.com/rf-peixoto/phishing_pot>
- Official licence: <https://github.com/rf-peixoto/phishing_pot/blob/main/LICENSE>
- Permitted project label: `1` (phishing) only; this source is not a legitimate
  or generic-spam corpus.
- The repository is recorded as CC BY-NC 4.0 (`verified_restricted_noncommercial`):
  attribution is required and commercial use is prohibited. Any future use
  must preserve the attribution notice, licence link, source/version/date, and
  a description of local modifications.
- CC BY-NC does not settle rights in the captured messages. Each sample may
  contain third-party text, logos, sender identities, attachments, or linked
  material; sample-level rights and a research/public-interest basis must be
  recorded before acceptance.
- Raw EML redistribution is disabled. Do not commit raw or derived private
  message content, and do not use the source in a commercial deployment.

## Required sample-level checks

For every candidate, record a decision and reviewer evidence for each item:

1. **Privacy and redaction:** remove or reject honeypot recipient addresses,
   recipient identifiers in body text and URL query/fragment parameters,
   personal names, account tokens, tracking IDs, and other third-party
   identifiers. Preserve only irreversible hashes for overlap checks.
2. **Encoded content:** decode MIME transfer encodings and Base64 locally for
   inspection only. Search decoded text, headers, URLs, and attachment metadata
   for residual addresses, credentials, tracking tokens, and unsafe payload
   indicators. Never execute decoded content.
3. **HTML and links:** treat HTML as inert text; sanitise/extract visible text
   without rendering. Never fetch, resolve, or contact any URL or domain found
   in a message. Record URL and parameter privacy risk without reputation lookups.
4. **Attachments and malware safety:** retain filename, media type, size, and
   cryptographic hash only. Do not open, unpack, scan by executing, or publish
   attachment bytes. Reject samples whose handling cannot be made safe.
5. **Phishing taxonomy:** accept only messages with evidence of credential,
   payment, account, identity, or other actionable deception. Classify generic
   advertising/spam, scams without a phishing action, and ambiguous lures as
   `spam_not_phishing`, `scam_not_phishing`, or `ambiguous`; never force label 1.
6. **Language:** require English for the primary model. Reject non-English or
   uncertain short messages; retain language evidence without raw text.
7. **Campaign/template grouping:** derive deterministic campaign and template
   groups from normalized subject/body, sender infrastructure, linked domains,
   and attachment family. Do not contact infrastructure. Reject exact,
   near-duplicate, or cross-split campaign/template overlap.

## Capability and lifecycle gate

The registry entry `github_rf_peixoto_phishing_pot` remains `pending` with
`ingestion_enabled: false`, `development_allowed: false`,
`redistribution_allowed: false`, and privacy `pending_sample_review`.
`staging_allowed` (if later authorised) permits only an ignored, metadata-
controlled review under `data/staging/`; it does not permit download,
promotion, model training, or API use. A reviewer must explicitly approve the
source, each retained sample, attribution record, and non-commercial handling
plan before capabilities can be changed. Readiness reports must remain blocked
until those decisions and an independent source audit are complete.

## Required evidence packet before approval

- repository commit/tag and access date;
- licence/attribution record and non-commercial use confirmation;
- sample-level privacy and third-party-rights decisions;
- encoded-content and attachment safety log;
- English-language and phishing-vs-spam/scam decisions;
- duplicate, campaign, template, and train/external-overlap report;
- accepted/rejected counts and reviewer identities;
- explicit decision to keep raw content non-redistributable.

No source may be cloned, downloaded, ingested, promoted, or used for training
while any required item is pending or rejected.
