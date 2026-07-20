# PhishShield AI architecture

```mermaid
flowchart TD
  User[User pastes raw email] --> Frontend[Next.js App Router]
  Frontend -->|typed POST /api/v1/analyze| API[FastAPI]
  Frontend -->|GET /api/v1/health| Health[Health response]
  API --> Parse[In-memory RFC822 parser]
  Parse --> Features[Text/header/link/attachment metadata]
  Features --> Rules[Rule-based security indicators]
  Features --> Model[ModelManager]
  Registry[services/ml/models/registry.json] --> Model
  Model --> Candidate[Inactive hash-verified candidate]
  Rules --> Explain[Structured explanation]
  Candidate --> Explain
  Explain --> Response[PredictionResponse]
  Response --> Frontend
  Boundary[Privacy boundary: no persistence, HTML rendering, URL fetches, or attachment execution] -.-> API
```

The browser owns only the current input and result state. The production `/analyze` flow does not use the legacy scan-history/report workspace. The model manager lazy-loads the registry candidate, verifies pipeline/vectorizer/manifest hashes, and never changes the registry's `activated` state.
