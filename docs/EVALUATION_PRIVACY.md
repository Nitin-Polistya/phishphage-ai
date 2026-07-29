# Evaluation privacy and redaction

Evaluation curation is designed for local review of sensitive email without
putting raw content in Git or public reports.

## Storage boundary

Public manifests contain metadata, stable hashes, redacted subjects, counts,
and review state. `content_location` is a `local-only://sample_id` token. The
actual path map and raw candidate files remain local and ignored under
`services/ml/evaluation/private/` or another private operator-controlled
location. Public metadata never contains an absolute local path.

Do not commit real raw bodies, full personal email addresses, phone numbers,
private headers, authentication tokens, attachment bytes, or live malicious
URLs. URL presence and count are sufficient for the public queue.

## Curation controls

The curator reads RFC822/text/JSON/CSV inputs and extracts sender domain,
attachment MIME types, URL count, format, and a redacted subject. It does not
render HTML, fetch URLs, execute attachments, or infer labels. Content hashes
are deterministic after Unicode and line-ending normalization; normalized
hashes support overlap review without publishing message text.

Reviewer labels are imported from a separate CSV/JSON file. Model outputs,
probabilities, rule scores, filenames, and source label vocabularies are
explicitly rejected as label sources. Reviewers remain responsible for privacy
review before sharing notes or a manifest.

## Privacy gate

`privacy_status=pass` is required for the independent benchmark. Unknown
provenance, unresolved personal data, unsafe notes, raw content fields, an
absolute path, or an attachment that cannot be safely handled remains pending
or is excluded. Existing local raw datasets are preserved in place and are not
copied, relabeled, deleted, or deployed by this phase.
