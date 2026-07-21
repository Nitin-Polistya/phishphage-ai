# API Service

FastAPI backend infrastructure for the PhishPhage AI MVP.

## Included endpoints

- `GET /`
- `GET /health`
- `GET /api/v1/health` (includes Firebase status)
- `POST /api/v1/parser/preview` (development email parser)

## Email Parser

The email parser endpoint (`POST /api/v1/parser/preview`) accepts raw email content and returns a normalized parsed structure.

### Request

```json
{
  "raw_email": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody text"
}
```

### Response

```json
{
  "subject": "Test",
  "sender": {
    "name": null,
    "address": "sender@example.com"
  },
  "reply_to": null,
  "recipients": [
    {
      "name": null,
      "address": "recipient@example.com"
    }
  ],
  "cc": [],
  "date": "Mon, 1 Jan 2024 12:00:00 +0000",
  "message_id": "<abc123@example.com>",
  "body_text": "Body text",
  "body_html": null,
  "body_visible_text": "",
  "headers": { ... },
  "extracted_urls": [],
  "url_evidence": [],
  "attachments": []
}
```

### Validation

- Email content cannot be empty
- Maximum size: 2 MB
- Attachments are analyzed for metadata only (not stored)
- No URL fetching or execution

## Configuration

Environment variables are loaded with `pydantic-settings` from `apps/api/.env`.

### Machine-learning availability

- `ML_REGISTRY_PATH` identifies the tracked model registry. Relative paths are resolved from the repository root.
- `ML_MODEL_ID` selects the registry entry; the default is `phase-c-logistic-regression-v1`.
- `ML_ARTIFACT_PATH` optionally points to a mounted/downloaded copy of the selected artifact. It is accepted only when its SHA-256 matches the registry entry. There is no standalone-model fallback.
- `ML_REQUIRED=false` allows API startup when the approved artifact is unavailable; unified analysis returns HTTP 200 with deterministic rule results and `ml_analysis.status` set to `unavailable`.
- `ML_REQUIRED=true` makes the approved model a readiness requirement. Health returns HTTP 503 and analysis returns HTTP 503 when it cannot be loaded or verified.
- `ML_MARGINAL_ALERT_BAND=0.08` defines the maximum amount above the saved model threshold that can be treated as a marginal, uncorroborated alert. It does not change the model threshold.

The optional fallback does not manufacture a prediction: prediction, probabilities, threshold, and model version are `null`. Classification, risk score, and recommendations come from rules; incomplete Safe evidence is explicitly qualified and its displayed confidence is capped at 0.65.

The registry-selected deployment candidate is `services/ml/artifacts/phase_c_model_development_v1/deployment_candidate/fitted_pipeline.joblib` and stores a fixed phishing threshold of `0.50`. The registry hash is verified before loading. See [model artifact distribution](../../docs/MODEL_ARTIFACT_DISTRIBUTION.md) for fresh-clone setup and the release mechanism.

### Firebase Setup (Optional)

Firebase Admin SDK is included. To enable Firebase:

1. Set these environment variables:
   - `FIREBASE_PROJECT_ID`
   - `FIREBASE_CLIENT_EMAIL`
   - `FIREBASE_PRIVATE_KEY` (with literal newlines or escaped `\n`)

2. The API will initialize Firebase on startup if credentials are present.

3. If credentials are missing, Firebase will be marked as `not_configured` in health checks, and the API will continue to run normally.

## Run

From `apps/api`:

```powershell
uvicorn app.main:app --reload
```

The API will start successfully whether or not Firebase credentials are configured.

## Testing

Run unit tests from `apps/api`:

```powershell
pytest tests/ -v
```

Tests cover:
- Email address parsing
- URL extraction
- Multi-part email handling
- Attachment metadata extraction
- Input validation (size limits, empty content)
- HTML and plain-text body extraction

## Unified Analysis Pipeline

The API now features a unified analysis pipeline that integrates the email parser, a rule-based engine, and a machine learning classifier for robust phishing detection.

### Pipeline Workflow
1. **Parsing**: Raw email is normalized into a structured format.
2. **Rule Analysis**: A deterministic engine identifies threat signals across content, URLs, and headers.
3. **ML Inference**: The selected word TF-IDF + balanced Logistic Regression candidate provides a phishing probability and fixed saved decision threshold.
4. **Decision Fusion**: A decision engine fuses both outputs into a final classification.

### Decision Engine Logic
The final decision uses correlation-aware fusion:
- Rule categories use diminishing returns, so several tracking-infrastructure observations do not add linearly.
- A modest model-only alert can resolve to Safe only when aligned DKIM/DMARC supports the visible sender and no strong malicious rule evidence exists.
- A marginal alert within `ML_MARGINAL_ALERT_BAND` can also remain Safe with limited-authentication qualification when the sole rule finding is missing authentication, the rule score is at most 8, every actionable link aligns organizationally with the sender, and there is no failure, impersonation, sensitive request, attachment risk, hidden destination, or multi-category corroboration.
- Authentication never suppresses credential harvesting, payment fraud, deceptive destinations, or other high-severity evidence.
- A high ML probability requires medium/high actionable rule corroboration before reaching Phishing; low-severity infrastructure observations alone cannot do so.
- The final risk score combines the adjusted rule score and ML probability. `fusion_reason` explains the selected branch.

### Endpoint
- `POST /api/v1/analysis/preview`
- **Request**: Same as the parser (`{"raw_email": "..."}`)
- **Response**: A `UnifiedAnalysisResponse` containing:
    - `parser`: Normalized email data.
    - `rule_analysis`: Signals, rule risk score, and recommendations.
    - `ml_analysis`: Availability status, prediction, class probabilities, decision threshold, model version, and an optional safe reason.
    - `decision`: Final unified classification, risk score, and confidence.
    - `analysis_completeness`: `body_text_only`, `structured_fields`, `html_content`, or `complete_raw_email`, evidence-availability booleans, and any limited-evidence warning.
    - `engine_agreement`: explicit rule/ML agreement, disagreement, or ML-unavailable state.
    - additive diagnostics: `rule_raw_score`, `rule_adjusted_score`, `ml_prediction`, `ml_phishing_probability`, `ml_threshold`, `final_decision_confidence`, `rule_ml_agreement`, `fusion_reason`, `positive_authentication_evidence`, and `authentication_evidence_status`.
    - `analysis_freshness` and `stale_reason`: current results always have a null stale reason; stale results include the exact rule/model availability or version reason.

HTML is parsed locally and never rendered. URL evidence records `anchor_href`, `plain_text`, `form_action`, `image_src`, `css_resource`, `tracking_pixel`, `document_metadata`, or `namespace_or_dtd`. Only user-actionable sources receive transport, sensitive-action, and visible-destination analysis. Domain comparison uses an offline bundled Public Suffix List snapshot, so parent/subdomain relationships and multipart suffixes are handled without network access. Content rules receive decoded visible text only, excluding headers, transfer encodings, markup, CSS, URLs, scripts, and attachment payloads.

Authentication is represented as pass, fail, inconclusive, or missing. Missing evidence is not treated as failure. Aligned positive evidence is reported explicitly, and third-party Return-Path infrastructure is contextual only when DKIM/DMARC aligns, Reply-To is aligned, and no stronger malicious evidence exists. This is evidence correlation, not a provider allowlist.

### Sample Request
```json
{ "raw_email": "From: alice@example.com\nSubject: Verify your password\n\nPlease verify your password" }
```

### Testing
Run the full suite, including pipeline integration tests:
```powershell
pytest tests/ -v
```

### Real local ML verification

After training, run this from `services/ml`:

```powershell
python scripts/verify_api_integration.py
python scripts/verify_legitimate_regressions.py
```

The script uses FastAPI's test client to send eight non-mocked requests through `POST /api/v1/analysis/preview` with `ML_REQUIRED=true`. It verifies that ML is available, both probabilities are within `[0,1]` and sum to one, fusion runs, and rule-only fallback is not used. Results are written to `services/ml/reports/api_verification.json` without raw email bodies.

Current verification includes ordinary project and support mail, credential phishing, invoice and delivery scams, an account-suspension lure, legitimate security/password wording, explicit rule/ML disagreement, and the Facebook hidden-destination regression. See `services/ml/README.md` for provenance, exact configuration, calibration, metrics, and the academic-baseline disclaimer.

`verify_legitimate_regressions.py` additionally sends five sanitized authenticated `.eml` fixtures through the real endpoint and provisioned model. It rejects ML-unavailable, `rules-v1`, `ml-baseline`, or otherwise stale version results and writes metadata-only evidence to `services/ml/reports/legitimate_regression.json`.

