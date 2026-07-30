# PhishPhage AI brand guide

## Identity

- Canonical public name: **PhishPhage AI**
- Suggested tagline: **Explainable phishing detection with evidence-aware decision safety.**
- Short descriptor: Defensive email analysis for human review.
- Tone: calm, precise, evidence-led, privacy-conscious, and candid about uncertainty.

Compatibility-sensitive identifiers may remain in metadata or old reports, but they do not change the public product name and should not appear as alternate branding in new portfolio copy.

## Logo and icon usage

The current frontend mark is a blue shield with a light check. Keep the icon paired with the wordmark when space permits. At small sizes, use the shield alone only when the surrounding context already names PhishPhage AI.

Text/SVG-safe specification:

```text
Canvas: square 64x64 viewBox
Base: #2563EB blue rounded shield tile
Shield: #EFF6FF, centered with generous inset
Check: #2563EB, 5px round line, no gradients
Corner radius: 14px tile, visually calm rather than aggressive
Clear space: at least 0.5x the shield width on every side
```

Do not stretch, rotate, add a glow, place the mark over busy imagery, or recolor it so that the check loses contrast. Do not use a warning triangle as a substitute for the shield mark.

## Palette

| Role | Light | Dark | Use |
| --- | --- | --- | --- |
| Primary | `#2563EB` | `#60A5FA` | Actions, links, brand mark |
| Ink | `#0F172A` | `#F8FAFC` | Main text |
| Surface | `#FFFFFF` | `#111827` | Cards and app background |
| Border | `#E2E8F0` | `#334155` | Structure and separation |
| Safe/supportive | `#15803D` | `#4ADE80` | Confirmed protective evidence, never the only signal |
| Review | `#B45309` | `#FBBF24` | Needs-review state |
| High concern | `#B91C1C` | `#F87171` | Phishing/high-concern state |

Color must never be the only indicator. Pair state colors with labels, icons, and text such as `Safe presentation eligible`, `Needs review`, or `Unable to verify`.

## Typography and spacing

- Prefer the existing system/UI sans stack used by the frontend.
- Use sentence case for product text; reserve uppercase for short eyebrow labels.
- Keep headings direct and descriptive; avoid sensational security language.
- Use a 4px base spacing unit, with 8px/16px/24px/32px rhythm for cards and sections.
- Preserve generous whitespace around the logo and evidence cards.

## Light and dark examples

Light: white or near-white surface, slate text, blue action, thin slate border, and state labels with text/icons.

Dark: deep slate surface, light text, blue action, muted slate border, and slightly brighter state colors that remain readable against the surface.

## Voice

Say: “The message contains a sender-domain mismatch; verify through an independent channel.”

Avoid: “The AI caught a guaranteed attack.” Prefer evidence and a next step over certainty.

## Prohibited claims

Do not claim universal detection, 100% accuracy, enterprise deployment, commercial adoption, global deployment, production certification, live threat-intelligence coverage, attachment-content scanning, or that Firebase is required. Do not describe the model candidate as activated when the registry says `activated=false`.
