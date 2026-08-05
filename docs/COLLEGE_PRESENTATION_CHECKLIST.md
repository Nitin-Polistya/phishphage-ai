# College presentation checklist

## Before the presentation

- [ ] Charge the laptop and pack the charger.
- [ ] Disable sleep and screen-lock interruptions for the presentation window.
- [ ] Start the backend on port 8000.
- [ ] Start the frontend on port 3000, or document the 3001 fallback.
- [ ] Verify `/health` and `/ready`.
- [ ] Verify the model status shown by the frontend.
- [ ] Analyze the synthetic safe demo.
- [ ] Analyze the synthetic phishing demo.
- [ ] Clear personal browser history and remove unrelated tabs.
- [ ] Close `.env`, `.env.local`, and terminals containing secrets.
- [ ] Disable desktop notifications.
- [ ] Prepare offline screenshots from the screenshot plan.
- [ ] Prepare a short screen recording if one is required.
- [ ] Open the report, presentation, architecture diagram, and demo guide.
- [ ] Keep a backup copy of the submission package.

## During the presentation

- [ ] Introduce phishing as a human-review problem.
- [ ] State clearly that PhishPhage AI is an academic/research prototype.
- [ ] Show the architecture and privacy boundary.
- [ ] Demonstrate the safe synthetic case.
- [ ] Demonstrate the phishing-style synthetic case.
- [ ] Explain rules, model probability, fusion, and indicators.
- [ ] Explain precision and recall using the approved-gold results.
- [ ] State that recall is 0.5200 and false negatives are 24/50.
- [ ] Explain why the model remains inactive.
- [ ] Mention that Gemini is advisory-only and optional.
- [ ] Explain why human reviewers remain authoritative.
- [ ] Mention private datasets and review artifacts remain local.
- [ ] Explain limitations and future retraining requirements.
- [ ] Avoid claims of perfect accuracy, enterprise replacement, or guarantees.

## After the presentation

- [ ] Stop the frontend and backend servers.
- [ ] Close the browser and any recording software.
- [ ] Secure private review artifacts and environment files.
- [ ] Remove temporary screenshots containing sensitive data.
- [ ] Restore normal sleep, notifications, and network settings.
- [ ] Confirm no private artifacts were copied into the tracked repository.
