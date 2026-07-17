"""Attach the one-time external result to the locked Step 3 reports and bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parents[1]


def _metric_row(name: str, values: dict) -> str:
    return (
        f"| {name} | {values['accuracy']:.4f} | {values['precision']:.4f} | "
        f"{values['recall']:.4f} | {values['f1']:.4f} | {values['roc_auc']:.4f} | "
        f"{values['pr_auc']:.4f} | {values['false_positive_rate']:.4f} | "
        f"{values['false_negative_rate']:.4f} | `{values['confusion_matrix']}` |"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-metrics", default=ROOT / "reports" / "evaluation_metrics.json", type=Path)
    parser.add_argument("--step3-metrics", default=ROOT / "reports" / "evaluation_metrics_v3.json", type=Path)
    parser.add_argument("--external-evaluation", default=ROOT / "reports" / "external_evaluation_v3.json", type=Path)
    parser.add_argument("--diagnosis", default=ROOT / "reports" / "generalization_diagnosis.json", type=Path)
    parser.add_argument("--diagnosis-markdown", default=ROOT / "reports" / "generalization_diagnosis.md", type=Path)
    parser.add_argument("--training-summary", default=ROOT / "reports" / "training_summary.md", type=Path)
    parser.add_argument("--metadata", default=ROOT / "reports" / "metadata.json", type=Path)
    parser.add_argument("--model", default=ROOT / "models" / "phishshield_model.joblib", type=Path)
    args = parser.parse_args()

    baseline = json.loads(args.baseline_metrics.read_text(encoding="utf-8"))
    step3 = json.loads(args.step3_metrics.read_text(encoding="utf-8"))
    external_payload = json.loads(args.external_evaluation.read_text(encoding="utf-8"))
    external = external_payload["metrics"]
    before_external = baseline["final_external_benchmark"]["metrics"]
    before_grouped = baseline["internal_grouped_holdout"]
    after_grouped = step3["grouped_template_diagnostic"]

    step3["external_benchmark"] = {
        "rows": external_payload["dataset_rows"],
        "metrics": external,
        "used_for_selection": False,
        "evaluations_after_model_lock": 1,
    }
    args.step3_metrics.write_text(json.dumps(step3, indent=2, sort_keys=True), encoding="utf-8")

    diagnosis = json.loads(args.diagnosis.read_text(encoding="utf-8"))
    diagnosis["external_evaluation_status"] = "evaluated once after candidate and threshold lock"
    diagnosis["before_external_benchmark"] = before_external
    diagnosis["after_external_benchmark"] = external
    diagnosis["remaining_weaknesses"] = [
        "Grouped diagnostic recall remains 67.47%, leaving 27 of 83 phishing messages undetected.",
        "External recall fell from 95% to 80% even though accuracy remained 90% and FPR improved to 0%.",
        "Structured indicators were sparse because the training corpus is mostly body text rather than complete RFC822/HTML messages.",
        "Top features still include source-sensitive vocabulary such as your, account, click, and common business phrasing.",
        "The grouped after-result is selection-aware development evidence, not an untouched production estimate.",
    ]
    args.diagnosis.write_text(json.dumps(diagnosis, indent=2, sort_keys=True), encoding="utf-8")

    markdown = [
        "# Generalization Under Template Shift", "",
        "## Root cause", "",
        "The v2 corpus was 68.5% synthetic or targeted synthetic and contained 25 surface substitutions from each of only 24 general templates. Validation learned source and campaign vocabulary; its Brier score rose from 0.0571 on validation to 0.2765 under grouped template shift.", "",
        "Feature importance confirms continued lexical reliance: phishing weights emphasize `your`, `account`, `click`, and `click here`, while legitimate weights emphasize conversational business language such as `we`, `would`, `project`, and `team`.", "",
        "## Changes", "",
        "- Reserved the existing 178-row grouped diagnostic before cleaning.",
        "- Removed 428 canonical template duplicates, 5 semantic near-duplicates, and 2 non-English development rows.",
        "- Reduced synthetic contribution from 68.5% to 22.15%.",
        "- Clustered remaining synthetic records by source/scenario campaign and curated records by semantic template.",
        "- Compared word, word+character, and word+character+structured features with Logistic Regression and calibrated LinearSVC.",
        "- Kept the decision threshold fixed at 0.50.",
        "- Required grouped OOF validation F1 >= 0.85, then selected on the fixed grouped development diagnostic. The external set was evaluated once after lock.", "",
        "## Metrics", "",
        "| Evaluation | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR | Matrix |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        _metric_row("Grouped before", before_grouped),
        _metric_row("Grouped after", after_grouped),
        _metric_row("External before", before_external),
        _metric_row("External after", external), "",
        "Selected model: word TF-IDF (1,2) + balanced Logistic Regression, seed 42, fixed threshold 0.50.", "",
        "## Interpretation", "",
        "Grouped accuracy and F1 improved substantially, and grouped FPR fell to zero. Grouped recall did not improve: the model remains conservative and misses unfamiliar phishing language. External accuracy declined only 1.25 percentage points, but external recall fell 15 points; that is a material limitation and is not hidden.", "",
        "Structured indicators did not win. Most available rows lack complete sender, Reply-To, HTML, URL, and attachment context, so the structured branch cannot yet learn those signals reliably.", "",
        "## Remaining weaknesses", "",
        "- Grouped and external false negatives remain too high for production use.",
        "- The training source is small and still has source-specific lexical cues.",
        "- The external set is synthetic, templated, balanced, and only 80 unique rows.",
        "- The grouped after-result was used as a Step 3 development selection benchmark and is not an untouched final estimate.",
        "- This is an academic baseline, not production-grade phishing protection.", "",
    ]
    args.diagnosis_markdown.write_text("\n".join(markdown), encoding="utf-8")
    args.training_summary.write_text("\n".join(markdown), encoding="utf-8")

    bundle = joblib.load(args.model)
    bundle["evaluation_metrics"]["external_benchmark"] = step3["external_benchmark"]
    bundle["dataset_provenance"]["external_evaluations_after_model_lock"] = 1
    joblib.dump(bundle, args.model)
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    metadata["artifact_size_bytes"] = args.model.stat().st_size
    metadata["external_evaluation"] = step3["external_benchmark"]
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "grouped_f1_before": before_grouped["f1"],
        "grouped_f1_after": after_grouped["f1"],
        "external_accuracy_before": before_external["accuracy"],
        "external_accuracy_after": external["accuracy"],
        "external_recall_before": before_external["recall"],
        "external_recall_after": external["recall"],
        "model_size_bytes": args.model.stat().st_size,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

