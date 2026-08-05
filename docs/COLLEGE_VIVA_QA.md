# PhishPhage AI viva questions and answers

These answers describe the current academic prototype. They intentionally do
not claim production certification or guaranteed detection.

1. **What is phishing?**  Phishing is a social-engineering attempt to trick a
   recipient into revealing information, sending money, opening content, or
   taking another unsafe action.

2. **Why is phishing detection important?**  Email can combine trusted-looking
   identity claims with urgent actions, so early evidence review can reduce
   harmful clicks and disclosures.

3. **Why use machine learning?**  ML can learn recurring lexical patterns that
   are difficult to enumerate manually and can rank messages by probability.

4. **Why use rule-based analysis?**  Rules expose concrete evidence such as
   routing mismatch, authentication state, urgency, and link structure.

5. **Why combine rules and ML?**  They cover different weaknesses: ML provides
   learned text patterns while rules provide inspectable technical context.

6. **What does the system return?**  It returns classification, score,
   probability when available, model metadata, signals, explanations, and
   recommendations.

7. **What is precision?**  Precision is the share of predicted phishing
   messages that were actually phishing.

8. **What is recall?**  Recall is the share of actual phishing messages that
   the system identified.

9. **Why is recall lower here?**  The conservative candidate misses unfamiliar,
   source-shifted, low-lexical-overlap, or metadata-dependent phishing cases.

10. **Why not lower the threshold?**  A lower threshold may improve recall but
    can increase false positives; the current evidence does not justify that
    change without a new governed experiment.

11. **What is a false positive?**  A safe message classified as phishing.

12. **What is a false negative?**  A phishing message classified as non-phishing.

13. **Why are false negatives important?**  They represent missed attacks and
    are the primary current limitation: 24 of 50 approved phishing records
    were false negatives.

14. **What is ROC-AUC?**  ROC-AUC measures how well probabilities rank the two
    classes across possible thresholds.

15. **What is PR-AUC?**  PR-AUC summarizes the precision/recall relationship
    across thresholds and focuses on positive-class retrieval.

16. **What is calibration?**  Calibration asks whether predicted probabilities
    correspond to observed frequencies; a probability is not automatically a
    guarantee.

17. **What is the current approved-gold size?**  It contains 75 approved
    records: 25 safe and 50 phishing.

18. **What are the current headline results?**  Accuracy 0.6667, precision
    0.9630, recall 0.5200, F1 0.6753, ROC-AUC 0.8852, and PR-AUC 0.9247.

19. **What is the confusion matrix?**  At threshold 0.50 it is
    `[[24, 1], [24, 26]]`, ordered as safe/positive and phishing/positive.

20. **Why use a gold dataset?**  It provides a separately reviewed, provenance-
    controlled reference for evaluation and error analysis.

21. **Why is human review necessary?**  Labels require context, source review,
    adjudication, privacy decisions, and accountability that automation cannot
    reliably provide here.

22. **Why not trust source labels automatically?**  Source labels may describe
    spam, malware, or a different taxonomy and may not have verified provenance.

23. **Why is Gemini advisory-only?**  It is an optional external suggestion
    service; a human must approve the final label and production behavior.

24. **Does Gemini receive raw email?**  The intended review path sends sanitized
    evidence only when explicitly enabled; live analysis does not depend on it.

25. **Why use SQLite?**  SQLite is appropriate for a local academic review
    workspace with simple transactions, audit records, and no server database
    requirement.

26. **Why use Next.js?**  Next.js provides the React application structure,
    routing, build system, and a practical local demonstration interface.

27. **Why use FastAPI?**  FastAPI gives typed Python endpoints, validation,
    OpenAPI documentation, and a natural boundary around the parser and ML code.

28. **Why Logistic Regression?**  It is a strong, inspectable baseline for
    sparse TF-IDF text and is easier to govern than a larger model for this scope.

29. **Why not deep learning?**  The current data and academic scope do not
    justify the added compute, data, interpretability, and governance burden.

30. **Why is the model inactive?**  It remains a registry candidate because
    current evidence shows recall and coverage limitations; activation requires
    a separate release decision.

31. **How is privacy preserved?**  Email is parsed locally, HTML is not
    rendered, URLs are not fetched, attachments are not executed, and public
    reports exclude raw private content.

32. **What happens to raw emails?**  The runtime processes them in memory; any
    browser history is opt-in and sanitized, while private review material stays
    local.

33. **How are URLs handled?**  The parser extracts structural evidence but does
    not follow, resolve, or reputation-check the destination.

34. **Why no production deployment?**  The project is a college research
    prototype with incomplete coverage and no production certification.

35. **How would it scale?**  A production design would require authenticated
    service boundaries, durable storage, queueing, observability, privacy review,
    abuse controls, and an independently validated operating point.

36. **How would retraining work?**  First approve licensed and privacy-reviewed
    data, adjudicate labels, deduplicate and group campaigns, isolate evaluation,
    compare candidates, verify artifacts, and obtain a release decision.

37. **What are the main current limitations?**  Recall, source/campaign shift,
    small approved-gold size, limited retained metadata, English/template bias,
    and lack of live-world prevalence evidence.

38. **What tests exist?**  Backend pytest, ML tests, frontend Node tests,
    TypeScript, ESLint, Next build, compile checks, documentation links, and
    privacy/security scans.

39. **How does the API work?**  The frontend sends a bounded typed request;
    FastAPI parses it, runs rules and optional inference, applies fusion, and
    returns a structured response.

40. **What is a model registry?**  It records model identity, version, hashes,
    compatibility, calibration, threshold, and activation state.

41. **How is reproducibility handled?**  The repository separates dataset roles,
    records configuration and hashes, uses deterministic reports/tests, and
    documents the fixed threshold and model version.

42. **How are datasets separated?**  Training/development, validation,
    external evaluation, approved gold, synthetic fixtures, generated reports,
    and model artifacts have distinct roles and privacy boundaries.

43. **What is source shift?**  Source shift occurs when evaluation content comes
    from a different source distribution than development content.

44. **What is campaign shift?**  Campaign shift occurs when attack templates,
    infrastructure, or social-engineering patterns differ from training groups.

45. **Why does the project use explainability?**  Reviewers need to challenge a
    result, verify evidence, learn from errors, and avoid blind trust in a label.

46. **What future work is planned?**  More independent reviewed data, modern
    campaign coverage, richer lawful metadata, multilingual evaluation, and
    governed candidate comparison.

47. **What makes this different from a simple classifier?**  It combines local
    parsing, deterministic evidence, model governance, decision safety,
    explainability, privacy controls, and a human-approved gold workflow.

48. **Can a safe result be trusted completely?**  No. A low-risk result is not a
    guarantee; sensitive requests must be verified independently.

49. **Does a high score prove malicious intent?**  No. It indicates that the
    observed evidence matches learned or deterministic risk patterns.

50. **What is the main conclusion?**  The project demonstrates transparent,
    privacy-conscious human-supported analysis, while honestly showing that
    recall and coverage still require future research.
