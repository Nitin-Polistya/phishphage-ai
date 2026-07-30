# Social preview specification

## Canvas

- Size: 1280x640 pixels.
- Safe area: 72px inset on all sides; keep text within the central 1136x496 area.
- Format: SVG source for review, then PNG export for GitHub if desired.
- Background: deep slate `#0F172A` with a restrained blue radial accent.

## Content

1. PhishPhage AI shield mark and wordmark in the upper-left.
2. Tagline: “Explainable phishing detection with evidence-aware decision safety.”
3. A synthetic analyzer-result preview showing evidence, rule/ML disagreement, and a review-safe outcome.
4. Small motifs for parsing, evidence, model integrity, and safety fusion.
5. Footer note: “Defensive research project • human review required”.

## Exclusions

No personal information, real mailbox content, active or live malicious URLs, private artifact URLs, local filesystem paths, credentials, browser tabs, or misleading accuracy/performance numbers. Do not imply that a cloud deployment exists or that Firebase is required.

## Accessibility and export

The PNG must be accompanied by alt text: “PhishPhage AI portfolio preview showing an explainable email-risk result with evidence cards and a decision-safety panel.” Do not rely on the blue accent to communicate risk; the preview labels the state in text.

An SVG-safe source is provided at [`social-preview.svg`](social-preview.svg). Review the SVG manually before exporting and preserve the text as selectable vector text when possible.
