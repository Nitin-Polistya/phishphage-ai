"""Prepare the template-shift corpus and train the locked Step 3 winner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishshield_ml.config import MLConfig
from phishshield_ml.generalization import prepare_generalization_corpus, train_generalized_model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dataset", default=ROOT / "data" / "processed" / "english_core.csv", type=Path)
    parser.add_argument("--dataset-output", default=ROOT / "data" / "processed" / "english_core_v3.csv", type=Path)
    parser.add_argument("--grouped-diagnostic-output", default=ROOT / "data" / "processed" / "grouped_template_diagnostic_v2.csv", type=Path)
    parser.add_argument("--corpus-audit-output", default=ROOT / "reports" / "corpus_diversity_v3.json", type=Path)
    parser.add_argument("--baseline-metrics", default=ROOT / "reports" / "evaluation_metrics.json", type=Path)
    parser.add_argument("--model-output", default=ROOT / "models" / "phishshield_model.joblib", type=Path)
    parser.add_argument("--metrics-output", default=ROOT / "reports" / "evaluation_metrics_v3.json", type=Path)
    parser.add_argument("--diagnosis-output", default=ROOT / "reports" / "generalization_diagnosis.json", type=Path)
    parser.add_argument("--diagnosis-markdown", default=ROOT / "reports" / "generalization_diagnosis.md", type=Path)
    parser.add_argument("--max-features", type=int, default=MLConfig.max_features)
    args = parser.parse_args()

    baseline_metrics = json.loads(args.baseline_metrics.read_text(encoding="utf-8"))
    corpus_audit = prepare_generalization_corpus(
        args.baseline_dataset,
        args.dataset_output,
        args.grouped_diagnostic_output,
        args.corpus_audit_output,
    )
    summary = train_generalized_model(
        args.dataset_output,
        args.grouped_diagnostic_output,
        args.model_output,
        args.metrics_output,
        config=MLConfig(max_features=args.max_features, model_output=args.model_output, metrics_output=args.metrics_output),
    )
    after_metrics = json.loads(args.metrics_output.read_text(encoding="utf-8"))
    baseline_grouped = baseline_metrics["internal_grouped_holdout"]
    diagnosis = {
        "root_causes": {
            "source_bias": "The v2 core combined one small curated source with project-authored synthetic data; source formatting was predictive.",
            "template_memorization": "The v2 generator produced 25 substitutions from each of only 24 general templates.",
            "vocabulary_memorization": "High validation separation did not transfer to held-out template vocabulary; feature importance is reported separately.",
            "synthetic_vs_real_imbalance": "Synthetic share was 68.5% before cleaning; Step 3 reduces and reports it.",
            "duplicated_campaign_language": "Numeric, amount, URL, and ticket substitutions did not create independent campaigns.",
            "language_distribution": corpus_audit["language_distribution_before"],
            "class_imbalance": corpus_audit["class_counts_after"],
            "campaign_overlap": {"exact_text_overlap": 0, "diagnostic_used_for_selection": True},
            "calibration": {
                "before_validation_brier": baseline_metrics["validation_selected_threshold"]["brier_score"],
                "before_grouped_brier": baseline_grouped["brier_score"],
                "interpretation": "The large Brier-score increase under template shift shows overconfident source/template predictions.",
            },
        },
        "changes": {
            "fixed_threshold": 0.5,
            "threshold_tuned": False,
            "duplicates_removed": corpus_audit["duplicates_removed"],
            "campaign_groups_after": corpus_audit["campaign_groups_after"],
            "synthetic_percentage_after": corpus_audit["synthetic_percentage"],
            "feature_sets": ["word TF-IDF", "word + character TF-IDF", "word + character TF-IDF + structured security indicators"],
            "models": ["Logistic Regression", "Calibrated LinearSVC"],
        },
        "before_grouped_diagnostic": baseline_grouped,
        "after_grouped_diagnostic": after_metrics["grouped_template_diagnostic"],
        "after_grouped_oof_validation": after_metrics["validation"],
        "selected_candidate": after_metrics["selected_candidate"],
        "selection_rule": "require grouped OOF validation F1 >= 0.85, then optimize the fixed grouped template-shift development benchmark; external remains untouched",
        "external_evaluation_status": "sealed until the selected candidate is locked; run evaluate_model.py next",
        "acceptance_note": "Metrics are reported without threshold reduction. The grouped diagnostic is selection-aware development evidence; only the external benchmark remains untouched.",
    }
    args.diagnosis_output.parent.mkdir(parents=True, exist_ok=True)
    args.diagnosis_output.write_text(json.dumps(diagnosis, indent=2, sort_keys=True), encoding="utf-8")
    before = diagnosis["before_grouped_diagnostic"]
    after = diagnosis["after_grouped_diagnostic"]
    args.diagnosis_markdown.write_text("\n".join([
        "# Generalization Under Template Shift", "",
        "## Root cause", "",
        "The v2 corpus was dominated by repeated synthetic campaigns: 25 surface substitutions per template. Validation separation did not transfer to unseen template vocabulary, and calibration became overconfident under shift.", "",
        "## Leakage controls", "",
        "- The existing grouped diagnostic was reproduced and reserved before corpus cleaning.",
        "- Exact diagnostic text is excluded from development data.",
        "- Candidate selection requires strong grouped OOF validation, then uses the fixed grouped diagnostic as a development robustness benchmark.",
        "- The grouped after-metric is therefore selection-aware, not an untouched final estimate.",
        "- The threshold remains fixed at 0.50.",
        "- The external benchmark remains sealed until after candidate lock.", "",
        "## Grouped diagnostic", "",
        f"- Before: accuracy={before['accuracy']:.4f}, precision={before['precision']:.4f}, recall={before['recall']:.4f}, F1={before['f1']:.4f}, FPR={before['false_positive_rate']:.4f}, FNR={before['false_negative_rate']:.4f}.",
        f"- After: accuracy={after['accuracy']:.4f}, precision={after['precision']:.4f}, recall={after['recall']:.4f}, F1={after['f1']:.4f}, FPR={after['false_positive_rate']:.4f}, FNR={after['false_negative_rate']:.4f}.", "",
        f"Selected candidate: `{after_metrics['selected_candidate']}`.",
        "External results are appended only after the locked-model evaluation.", "",
    ]), encoding="utf-8")
    print(json.dumps({
        "model_version": summary.model_version,
        "selected_candidate": after_metrics["selected_candidate"],
        "grouped_f1_before": baseline_grouped["f1"],
        "grouped_f1_after": after_metrics["grouped_template_diagnostic"]["f1"],
        "synthetic_percentage_after": corpus_audit["synthetic_percentage"],
        "external_evaluated": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
