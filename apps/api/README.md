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
  "headers": { ... },
  "extracted_urls": [],
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

- `ML_MODEL_PATH` identifies the Joblib model bundle. Relative paths are resolved from the repository root. The default is `services/ml/models/phishshield_model.joblib`.
- `ML_REQUIRED=false` is the local MVP default. If the model cannot be loaded or inference fails, analysis returns HTTP 200 with the deterministic rule result and `ml_analysis.status` set to `unavailable`.
- `ML_REQUIRED=true` makes ML mandatory. Model load or inference failure returns HTTP 503 with a safe client message.

The optional fallback does not manufacture a prediction: prediction, probabilities, and model version are `null`. Its final classification, risk score, confidence, and recommendations come directly from the rule engine.

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
3. **ML Inference**: A TF-IDF + Logistic Regression model provides a probabilistic phishing prediction.
4. **Decision Fusion**: A decision engine fuses both outputs into a final classification.

### Decision Engine Logic
The final decision is based on a fusion of Rule-Based and ML results:
- **Agreement**: If both Rule-Based and ML engines agree (both 'phishing' or both 'safe'), the result is high-confidence.
- **Disagreement**: If the engines disagree, the system defaults to a **conservative 'suspicious'** classification unless one engine provides an overwhelmingly strong signal (e.g., Rule Score > 90 or ML Prob > 0.95).
- **Risk Score**: The final score is a weighted average of the rule-based risk score and the ML probability.

### Endpoint
- `POST /api/v1/analysis/preview`
- **Request**: Same as the parser (`{"raw_email": "..."}`)
- **Response**: A `UnifiedAnalysisResponse` containing:
    - `parser`: Normalized email data.
    - `rule_analysis`: Signals, rule risk score, and recommendations.
    - `ml_analysis`: Availability status, prediction, class probabilities, model version, and an optional safe reason.
    - `decision`: Final unified classification, risk score, and confidence.

### Sample Request
```json
{ "raw_email": "From: alice@example.com\nSubject: Verify your password\n\nPlease verify your password" }
```

### Testing
Run the full suite, including pipeline integration tests:
```powershell
pytest tests/ -v
```

