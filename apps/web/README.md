# PhishShield AI web application

The frontend is a Next.js App Router application. It provides an in-memory raw-email analysis workspace at `/analyze` and reads the production FastAPI inference service.

## Local development

From the repository root:

```powershell
# terminal 1
apps\api\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir apps/api

# terminal 2
cd apps/web
npm install
Copy-Item .env.example .env.local
npm run dev
```

The web app runs at `http://localhost:3000`; the API runs at `http://localhost:8000`. Set `NEXT_PUBLIC_API_BASE_URL` in `.env.local` when the API uses a different local address.

The Analyze workspace calls `POST /api/v1/analyze` and polls `GET /api/v1/health` for actual backend/model status. The response is held only in React memory; raw email is not written to localStorage, sessionStorage, analytics, or a database. Email HTML is never rendered and detected URLs are displayed as non-clickable text.

## Checks

```powershell
npm run lint
npx tsc --noEmit
npm test
npm run build
```

If the status shows Offline, start the API and confirm CORS allows `http://localhost:3000`. A degraded status means the API is reachable but has no loaded inference candidate. Automated results support human review and are not guarantees of safety.
