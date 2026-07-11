"""Decision engine for fusing rule-based and ML analysis results."""

from __future__ import annotations

from app.schemas.analysis import AnalysisResult, DecisionResult, ThreatClassification


def fuse_analysis_results(rule_result: AnalysisResult, ml_prediction: str, ml_probability: float) -> DecisionResult:
    """
    Fuses rule-based analysis and ML inference into a final decision.
    
    Fusion Algorithm:
    1. Convert ML probability to a 0-100 scale.
    2. Compute a weighted average of the risk scores.
    3. Determine classification based on agreement and score thresholds.
    
    Decision Logic:
    - If both agree on 'phishing' (Rule >= 70 and ML >= 0.7) -> phishing
    - If both agree on 'safe' (Rule < 30 and ML < 0.3) -> safe
    - If they disagree:
        - If either is overwhelmingly certain (Rule > 90 or ML > 0.95) -> follow the certain one
        - Otherwise -> suspicious (conservative approach)
    """
    rule_score: int = rule_result.risk_score
    ml_score: float = ml_probability * 100
    
    # Calculate final risk score as average
    final_score: int = int((rule_score + ml_score) / 2)
    
    # Determine classification
    rule_class = rule_result.classification
    ml_class = "phishing" if ml_prediction == "phishing" else "safe"
    
    if rule_class == ThreatClassification.phishing and ml_class == "phishing":
        final_classification = ThreatClassification.phishing
    elif rule_class == ThreatClassification.safe and ml_class == "safe":
        final_classification = ThreatClassification.safe
    else:
        # Disagreement case: be conservative
        if rule_score > 90 or ml_probability > 0.95:
            final_classification = ThreatClassification.phishing if (rule_score > 90 or ml_probability > 0.95) else ThreatClassification.suspicious
            # If rule was the strong one
            if rule_score > 90: final_classification = ThreatClassification.phishing
            # If ML was the strong one
            if ml_probability > 0.95: final_classification = ThreatClassification.phishing
        elif rule_score < 10 and ml_probability < 0.1:
            final_classification = ThreatClassification.safe
        else:
            final_classification = ThreatClassification.suspicious

    # Final score adjustment for classification consistency
    # Ensure phishing classification has a high score and safe has a low score
    if final_classification == ThreatClassification.phishing and final_score < 70:
        # We don't force the score, but the classification takes priority
        pass

    # Confidence is based on agreement
    # If they agree, confidence is higher. If they disagree, confidence is lower.
    agreement = 1.0 if (rule_class == ThreatClassification.phishing and ml_class == "phishing") or \
                      (rule_class == ThreatClassification.safe and ml_class == "safe") else 0.5
    
    # Combine agreement with the average of individual confidences
    # Rule confidence is in rule_result.confidence, ML confidence is ml_probability (for phishing) 
    # or (1-ml_probability) for legitimate.
    ml_conf: float = ml_probability if ml_prediction == "phishing" else (1.0 - ml_probability)
    final_confidence: float = (rule_result.confidence + ml_conf + agreement) / 3.0

    return DecisionResult(
        classification=final_classification,
        risk_score=final_score,
        confidence=round(final_confidence, 2)
    )
