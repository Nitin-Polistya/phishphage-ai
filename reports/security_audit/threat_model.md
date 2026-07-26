# Threat model

## Assets

Raw email in memory, parsed headers/body/URL evidence, attachment metadata, model artifacts and registry integrity data, Firebase credentials, browser scan history/preferences, generated reports, and availability of analysis endpoints.

## Actors and entry points

An unauthenticated Internet client can reach the frontend routes `/`, `/analyze`, `/dashboard`, `/history`, `/reports`, and `/settings`, and the API root, health routes, parser preview, analysis preview, and production analyze route. A malicious sender controls email text, headers, HTML, URLs, MIME structure, and filenames. A deployment operator controls environment variables and mounted artifacts.

## Trust boundaries

Browser → Next.js; Next.js → FastAPI; FastAPI → parser; parser → rule/ML pipeline; pipeline → trusted local artifact; browser → local storage; optional application → Firebase; deployment platform → environment variables/artifacts.

## Abuse cases and mitigations

Oversized or deeply structured MIME input is bounded by request bytes, header lines, MIME parts, attachment count, and URL count. HTML/script and tracking content is parsed as data only; URLs are not fetched. XSS and report injection are mitigated by React text rendering plus HTML escaping and CSV formula-prefix protection. Request floods are bounded by configurable process-local limits. Model path escape and registry/artifact hash mismatch fail closed before deserialization. CORS, request IDs, safe errors, no-store API responses, CSP, and standard security headers reduce browser and information-leakage risk.

## Residual risks

The API has no authentication or authorization; process-local rate limits do not coordinate across instances; trusted Joblib/Pickle loading remains unsafe if an operator supplies a malicious artifact; Firebase is optional and currently not an authorization layer; production proxy/TLS configuration remains deployment responsibility.
