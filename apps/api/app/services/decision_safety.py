"""Deterministic presentation safety for analysis results.

This module never changes an ML probability, threshold, calibration value, or
rule score. It decides whether those underlying values are complete enough to
support a user-facing safe verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.schemas.analysis import AnalysisCompletenessLevel, DecisionSafetyStatus, PresentationState, ThreatClassification


def _value(source: Any, key: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _nested(source: Any, path: str, default: Any = None) -> Any:
    current = source
    for key in path.split('.'):
        current = _value(current, key, None)
        if current is None:
            return default
    return current


def _enum_value(value: Any) -> str | None:
    return getattr(value, 'value', value) if value is not None else None


def _signals(source: Any) -> list[Any]:
    rule_signals = _nested(source, 'rule_analysis.signals', None)
    if isinstance(rule_signals, list):
        return rule_signals
    return _value(source, 'signals', []) or []


@dataclass(frozen=True)
class SafetyAssessment:
    analysis_state: AnalysisCompletenessLevel
    status: DecisionSafetyStatus
    presentation_state: PresentationState
    safe_verdict_allowed: bool
    requires_rescan: bool
    missing_evidence: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)


def can_present_safe_verdict(result: Any) -> bool:
    """Return whether *result* may be presented as safe or low risk.

    The function accepts a Pydantic response or a plain dictionary so it can be
    used by API, report migration, and frontend-oriented regression tests.
    """
    freshness = _enum_value(_value(result, 'analysis_freshness'))
    if freshness != 'current':
        return False

    completeness = _value(result, 'analysis_completeness')
    status = _enum_value(_value(result, 'analysis_completeness_status'))
    if status in {'partial', 'incomplete', 'unavailable', 'stale'}:
        return False
    if completeness is not None and _enum_value(_value(completeness, 'analysis_state')) in {'partial', 'incomplete', 'unavailable', 'stale'}:
        return False

    if _value(result, 'parser_success', True) is False:
        return False
    if _value(result, 'fusion_performed', True) is False:
        return False
    engines_completed = set(_value(result, 'engines_completed', []) or [])
    if engines_completed and not {'rules', 'ml'}.issubset(engines_completed):
        return False
    if _enum_value(_nested(result, 'ml_analysis.status', _value(result, 'ml_status', None))) != 'available':
        return False
    if _value(result, 'rule_analysis', None) is None and _value(result, 'rule_raw_score', None) is None:
        return False
    if _enum_value(_value(result, 'rule_ml_agreement', None)) in {None, 'ml_unavailable'}:
        return False

    reasons = set(_value(result, 'incomplete_reason_codes', []) or [])
    if reasons & {
        'parser_failed', 'rules_unavailable', 'ml_unavailable', 'fusion_missing',
        'url_extraction_failed', 'contradictory_metadata', 'provenance_unverified',
    }:
        return False
    if bool(_value(result, 'link_language_present', False)) and int(_value(result, 'actual_url_count', 0) or 0) == 0:
        return False
    for signal in _signals(result):
        code = _value(signal, 'code', '')
        severity = _enum_value(_value(signal, 'severity'))
        confidence = _value(signal, 'confidence', None)
        if code in {'identity_claim_sender_domain_mismatch', 'sensitive_brand_claim_requires_review'}:
            if code == 'sensitive_brand_claim_requires_review' or severity == 'high' or (confidence is not None and confidence >= 0.8):
                return False
        if code == 'url_destination_unverified':
            return False
    return True


def assess_decision_safety(
    *,
    parser_success: bool,
    rule_available: bool,
    ml_available: bool,
    fusion_performed: bool,
    freshness: str,
    stale_reason: str | None,
    parsed: Any = None,
    rule_result: Any = None,
    input_evidence_complete: bool = True,
    provenance_verified: bool = True,
    contradictory_reason_codes: list[str] | None = None,
) -> SafetyAssessment:
    missing: list[str] = []
    reasons: list[str] = list(contradictory_reason_codes or [])

    if not parser_success:
        missing.append('parser output')
        reasons.append('parser_failed')
    if not rule_available:
        missing.append('rule analysis')
        reasons.append('rules_unavailable')
    if not ml_available:
        missing.append('ML inference')
        reasons.append('ml_unavailable')
    if not fusion_performed:
        missing.append('rule/ML fusion')
        reasons.append('fusion_missing')
    if not provenance_verified:
        missing.append('verified engine provenance')
        reasons.append('provenance_unverified')
    if not input_evidence_complete:
        missing.append('complete source evidence')
        reasons.append('input_evidence_partial')
    if freshness != 'current':
        reasons.append('stale_result')
        if stale_reason:
            missing.append('fresh engine result')

    if parsed is not None:
        if getattr(parsed, 'link_language_present', False) and getattr(parsed, 'actual_url_count', 0) == 0:
            missing.append('verifiable link destination')
            reasons.append('url_extraction_failed')

    signals = list(getattr(rule_result, 'signals', []) or [])
    for signal in signals:
        code = getattr(signal, 'code', '')
        if code == 'identity_claim_sender_domain_mismatch':
            confidence = getattr(signal, 'confidence', None)
            if _enum_value(getattr(signal, 'severity', None)) == 'high' or (confidence is not None and confidence >= 0.8):
                reasons.append('claimed_brand_sender_mismatch')
        elif code == 'sensitive_brand_claim_requires_review':
            reasons.append('sensitive_claim_unverified')
        elif code == 'url_destination_unverified':
            reasons.append('url_extraction_failed')

    reasons = list(dict.fromkeys(reasons))
    if freshness != 'current':
        state = AnalysisCompletenessLevel.unavailable if not ml_available or not rule_available or not parser_success else AnalysisCompletenessLevel.stale
        status = DecisionSafetyStatus.rescan_required
        presentation = PresentationState.rescan_required
        requires_rescan = True
    elif not parser_success or not rule_available or not ml_available or not fusion_performed:
        state = AnalysisCompletenessLevel.unavailable if not ml_available and not rule_available else AnalysisCompletenessLevel.incomplete
        status = DecisionSafetyStatus.unable_to_verify
        presentation = PresentationState.unable_to_verify
        requires_rescan = False
    elif reasons:
        state = AnalysisCompletenessLevel.partial
        status = DecisionSafetyStatus.needs_review
        presentation = PresentationState.needs_review
        requires_rescan = 'url_extraction_failed' in reasons
    else:
        state = AnalysisCompletenessLevel.complete
        status = DecisionSafetyStatus.eligible
        presentation = PresentationState.safe
        requires_rescan = False

    allowed = status == DecisionSafetyStatus.eligible and not reasons
    return SafetyAssessment(
        analysis_state=state,
        status=status,
        presentation_state=presentation,
        safe_verdict_allowed=allowed,
        requires_rescan=requires_rescan,
        missing_evidence=list(dict.fromkeys(missing)),
        reason_codes=reasons,
    )
