# Terminology consistency audit

## Canonical public name

The canonical public product name is **PhishShield AI**. Evidence includes the root README, frontend package name `@phishshield/web`, frontend report payload product name, current UI copy, and recent public-facing documentation.

## Inconsistent internal references

The following references still use `PhishPhage`:

- API defaults and root response: `APP_NAME`, FastAPI description, and root message.
- ML package description and historical services/ML documentation.
- Browser-local storage keys and some test fixture keys.
- Older research/report/source names and historical comments.

These are internal identifiers or compatibility surfaces. They were not broadly renamed because that would exceed a documentation-only phase and could change storage/API behavior. New public documentation uses PhishShield AI and explains the distinction where needed.

## Recommended follow-up

If branding cleanup is approved later, migrate user-visible API labels and browser-storage keys with an explicit compatibility plan. Do not rename model IDs, registry entries, report/source identifiers, or API fields as part of a cosmetic change.
