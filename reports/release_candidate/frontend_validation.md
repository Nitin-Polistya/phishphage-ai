# Frontend validation gate

Status: **Pass for local tool checks; clean-install gate inconclusive.**

- `npm test`: **33 passed**, 0 failed.
- `npx --no-install tsc --noEmit`: pass.
- `npm run lint`: pass.
- `npm run build`: pass with Next.js `15.5.21`.
- `npm audit`: **0 vulnerabilities**.
- `npm ci`: timed out after approximately five minutes in both sandboxed and escalated environments without package-manager output. The available dependency tree eventually restored enough tools for all local checks, but a clean-install reproduction is still required.

Build route output:

| Route | Size | First-load JS |
| --- | ---: | ---: |
| `/` | 1.42 kB | 118 kB |
| `/analyze` | 16.6 kB | 124 kB |
| `/dashboard` | 4.88 kB | 149 kB |
| `/history` | 6.57 kB | 151 kB |
| `/reports` | 8.16 kB | 156 kB |
| `/settings` | 7.96 kB | 132 kB |
| Shared JS | — | 103 kB |

The browser security suite was not claimed as passed because prior host policy blocked Playwright/Chromium child processes.

An existing local port-3000 process returned HTTP 200 for `/`, `/dashboard`, `/analyze`, `/history`, `/reports`, and `/settings`. Its startup log predates the RC metadata change, so a fresh `npm start` check remains unchecked until the clean `npm ci` gate is resolved.
