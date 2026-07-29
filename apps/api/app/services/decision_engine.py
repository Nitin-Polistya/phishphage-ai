"""Decision engine for fusing rule and ML evidence without double-counting."""

from __future__ import annotations

from dataclasses import replace

from app.schemas.analysis import AnalysisResult, DecisionResult, ThreatClassification
from app.services.risk_scoring import calculate_raw_risk_score
from app.services.safety_fusion import FUSION_POLICY_VERSION, evaluate_high_confidence_rule_evidence, evaluate_safety_floor


def fuse_analysis_results(
    rule_result: AnalysisResult,
    ml_prediction: str,
    ml_probability: float,
    *,
    authenticated_sender: bool = False,
    strong_malicious_evidence: bool = False,
    ml_threshold: float = 0.5,
    marginal_alert_band: float = 0.08,
    marginal_alert_eligible: bool = False,
    parsed_email=None,
) -> DecisionResult:
    """Fuse independently useful evidence, treating modest ML scores as uncertain.

    Positive authentication can resolve a weak model-only alert, but never suppresses
    high-severity malicious content, deceptive destinations, or overwhelming ML evidence
    that is corroborated by rule evidence.
    """
    rule_score = rule_result.risk_score
    ml_score = ml_probability * 100
    rule_class = rule_result.classification
    ml_class = 'phishing' if ml_prediction == 'phishing' else 'safe'
    has_medium_or_high_rule = any(
        signal.score > 0 and signal.severity.value in {'medium', 'high'}
        for signal in rule_result.signals
    )

    if rule_class == ThreatClassification.phishing and ml_class == 'phishing':
        classification = ThreatClassification.phishing
        reason = 'Independent rule and ML evidence agree on phishing.'
    elif rule_class == ThreatClassification.safe and ml_class == 'safe':
        classification = ThreatClassification.safe
        reason = 'Rule and ML evidence agree on a safe result.'
    elif (
        rule_class == ThreatClassification.safe
        and authenticated_sender
        and not strong_malicious_evidence
        and ml_probability < 0.70
    ):
        classification = ThreatClassification.safe
        reason = 'A modest model-only alert was not corroborated, while aligned authentication supported the sender identity.'
    elif (
        marginal_alert_eligible
        and ml_prediction == 'phishing'
        and ml_threshold < ml_probability <= ml_threshold + marginal_alert_band
    ):
        classification = ThreatClassification.safe
        reason = (
            'The marginal ML alert was not corroborated: rules found only missing authentication evidence, '
            'and all actionable links align with the sender organization.'
        )
    elif ml_probability > 0.95 and has_medium_or_high_rule:
        classification = ThreatClassification.phishing
        reason = 'Overwhelming ML probability is corroborated by actionable rule evidence.'
    elif rule_score > 90 and strong_malicious_evidence:
        classification = ThreatClassification.phishing
        reason = 'Multiple strong malicious rule findings outweigh the ML disagreement.'
    else:
        classification = ThreatClassification.suspicious
        reason = 'Rule and ML evidence disagree or lack enough independent corroboration for a definitive verdict.'

    pre_floor_score = int((rule_score + ml_score) / 2)
    final_score = pre_floor_score
    if classification == ThreatClassification.phishing:
        final_score = max(70, final_score)
    elif classification == ThreatClassification.safe:
        final_score = min(29, final_score)

    evidence = replace(
        evaluate_high_confidence_rule_evidence(rule_result.signals, parsed_email),
        rule_adjusted_score=rule_score,
    )
    floor = evaluate_safety_floor(rule_score, evidence)
    if floor.applied:
        classification_rank = {ThreatClassification.safe: 0, ThreatClassification.suspicious: 1, ThreatClassification.phishing: 2}
        if floor.classification_floor and classification_rank[floor.classification_floor] > classification_rank[classification]:
            classification = floor.classification_floor
        if floor.minimum_final_score is not None:
            final_score = max(final_score, floor.minimum_final_score)

    agreement = 1.0 if (
        rule_class == ThreatClassification.phishing and ml_class == 'phishing'
    ) or (rule_class == ThreatClassification.safe and ml_class == 'safe') else 0.5
    ml_confidence = ml_probability if ml_prediction == 'phishing' else 1.0 - ml_probability
    final_confidence = (rule_result.confidence + ml_confidence + agreement) / 3.0
    if authenticated_sender and classification == ThreatClassification.safe and ml_class == 'phishing':
        final_confidence = min(0.82, final_confidence + 0.08)
    limited_authentication_evidence = bool(
        classification == ThreatClassification.safe and marginal_alert_eligible
        and ml_prediction == 'phishing' and ml_threshold < ml_probability <= ml_threshold + marginal_alert_band
    )
    if limited_authentication_evidence:
        final_confidence = min(0.60, final_confidence)

    disagreement = rule_class != (ThreatClassification.phishing if ml_class == 'phishing' else ThreatClassification.safe)
    disagreement_resolution = None
    if disagreement:
        disagreement_resolution = (
            'Rules found corroborated deterministic evidence; the lower ML probability remains visible, '
            'but the final decision prioritizes the safety floor.'
            if floor.applied else
            'Rule and ML evidence disagree; no safety floor was justified by the available independent families.'
        )
    fusion_reason = reason
    if floor.applied:
        fusion_reason = (
            f'{floor.reason} The ML model assigned {ml_probability:.3f} phishing probability; '
            f'the deterministic safety floor raised the pre-floor score from {pre_floor_score} to {final_score}.'
        )
    dominant_source = 'rules' if floor.applied else 'ml' if ml_probability >= 0.8 and rule_score < 30 else 'balanced'
    return DecisionResult(
        classification=classification,
        risk_score=final_score,
        confidence=round(final_confidence, 2),
        fusion_reason=fusion_reason,
        limited_authentication_evidence=limited_authentication_evidence,
        decision_source='rule_ml_fusion',
        fusion_performed=True,
        fallback_used=False,
        fallback_reason=None,
        fusion_policy_version=FUSION_POLICY_VERSION,
        fusion_inputs={
            'rule_raw_score': calculate_raw_risk_score(rule_result.signals),
            'rule_adjusted_score': rule_score,
            'ml_probability': ml_probability,
            'ml_score': ml_score,
            'ml_prediction': ml_prediction,
            'ml_threshold': ml_threshold,
            'pre_floor_score': pre_floor_score,
        },
        fusion_components=['rule_adjusted_score', 'ml_probability_x_100'],
        rule_weight=0.5,
        ml_weight=0.5,
        applied_floor=floor.applied,
        applied_floor_reason=floor.reason,
        dominant_evidence_source=dominant_source,
        disagreement_resolution=disagreement_resolution,
        safety_floor_applied=floor.applied,
        safety_floor_rule_id=floor.rule_id,
        pre_floor_score=pre_floor_score,
        post_floor_score=final_score,
        evidence_families=list(evidence.independent_families),
        high_confidence_rule_evidence=evidence.high_confidence,
        protective_evidence=list(evidence.protective_evidence),
    )
