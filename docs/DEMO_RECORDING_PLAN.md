# Demo recording plan

Do not record automatically as part of documentation work. A human should review the browser state, synthetic data, and final export before publishing.

## Recording setup

- Primary resolution: 1920x1080 source, with the browser content captured at 1440x900 or larger.
- Export: MP4/H.264 for video; GIF only for a short looping excerpt. Keep a WebM copy if the portfolio host supports it.
- Browser: clean Chromium/Firefox profile, 100% zoom, no extensions, no saved form data, no personal history, and no unrelated tabs.
- Theme: light for the primary flow; one short dark-theme clip for the decision-safety panel if it improves contrast.
- Cursor: move deliberately, pause over headings and evidence cards, and do not hover over private browser chrome.
- Clip length: 3-5 minutes total; individual clips should be 8-25 seconds with short crossfades or direct cuts.
- Captions: open captions for every talking point, plus a text label when the model is unavailable or the result requires review.

## Route order

1. `/` landing page.
2. `/analyze` input modes.
3. Safe fixture scan.
4. Synthetic impersonation fixture scan.
5. Decision-safety and indicators panels.
6. `/history` and `/reports` with sanitized local records.
7. `/settings` privacy preference and theme.
8. `/docs`, `/api/v1/health`, and `/ready` for the technical appendix.
9. Architecture diagram and limitations slide.

## Privacy checklist before recording

- [ ] Only `example.com`, `example.org`, or `example.net` addresses and destinations are visible.
- [ ] No personal names, mailbox exports, raw headers, authentication tokens, secrets, or private business information.
- [ ] No browser profile identifiers, address bar private paths, terminal windows, or unrelated tabs.
- [ ] No active URL is opened, followed, or presented as verified.
- [ ] The displayed model/readiness status is the actual local status.
- [ ] The final score and raw probability are not edited after capture.
- [ ] Attachment content is not shown or implied to be scanned.

## Editing and export

Use a short title card, readable zoom, captions, and a final limitations card. Blur or crop browser chrome only after confirming that no context is being hidden in a misleading way. Keep the source recording private until review. For GitHub, prefer a compressed short GIF under the repository's current upload limit or link to an external video; do not add a large binary to Git without checking repository policy. The recording is not a substitute for README text or an accessible caption transcript.
