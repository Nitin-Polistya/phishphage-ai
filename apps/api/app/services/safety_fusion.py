"""Evidence-family-based asymmetric safety floors for rule/ML fusion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from app.analyzers.brand_identity import BRAND_DOMAIN_FAMILIES, assess_claimed_brand
from app.analyzers.header_analyzer import evaluate_authentication
from app.schemas.analysis import AuthenticationState, ThreatClassification, ThreatSignal
from app.services.domain_utils import domains_align
from app.services.risk_scoring import calculate_raw_risk_score


FUSION_POLICY_VERSION = 'asymmetric-safety-v1'
PERSONAL_MAILBOX_DOMAINS = frozenset({'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'aol.com'})

IDENTITY_CODES = frozenset({
    'header_displayname_impersonation',
    'identity_claim_sender_domain_mismatch',
    'sensitive_brand_claim_requires_review',
})
ROUTING_CODES = frozenset({'header_replyto_mismatch', 'header_returnpath_mismatch', 'header_invalid_returnpath'})
AUTH_CODES = frozenset({
    'header_spf_fail', 'header_spf_inconclusive', 'header_spf_none', 'header_spf_conflicting', 'header_spf_malformed',
    'header_dkim_fail', 'header_dkim_inconclusive', 'header_dkim_none', 'header_dkim_conflicting', 'header_dkim_malformed',
    'header_dmarc_fail', 'header_dmarc_inconclusive', 'header_dmarc_none', 'header_dmarc_conflicting', 'header_dmarc_malformed',
    'header_missing_authentication',
})
ACTION_CODES = frozenset({
    'content_credential_request', 'content_payment_request', 'content_mfa_bypass',
    'content_account_verification', 'content_banking_alert', 'content_government_notice',
    'content_suspicious_cta', 'content_fear_tactics', 'content_crypto_scam',
    'content_gift_card_scam', 'mailto_destination_mismatch', 'url_suspicious_keyword',
})
INFRASTRUCTURE_CODES = frozenset({
    'url_trusted_text_unrelated_destination', 'url_visible_href_mismatch', 'url_sender_domain_mismatch',
    'url_ip_host', 'url_punycode', 'url_homograph', 'url_lookalike_domain', 'url_shortener',
    'url_suspicious_tld', 'url_userinfo', 'url_tracking_pixel',
})
SENSITIVE_ACTION_CODES = frozenset({
    'content_credential_request', 'content_payment_request', 'content_mfa_bypass',
    'content_account_verification', 'content_banking_alert', 'content_government_notice',
    'content_crypto_scam', 'content_gift_card_scam', 'mailto_destination_mismatch',
})
GOVERNMENT_LEGAL_CODES = frozenset({'content_government_notice', 'content_fear_tactics', 'identity_claim_sender_domain_mismatch'})


@dataclass(frozen=True)
class EvidenceSummary:
    rule_raw_score: int
    rule_adjusted_score: int
    independent_families: tuple[str, ...]
    family_codes: dict[str, tuple[str, ...]]
    markers: frozenset[str]
    high_severity_codes: tuple[str, ...]
    protective_evidence: tuple[str, ...]
    strong_correlated: bool
    moderate_correlated: bool
    official_brand_domain: bool
    aligned_authentication: bool
    sensitive_action: bool
    external_actionable_destination: bool
    personal_mailto_destination: bool

    @property
    def high_confidence(self) -> bool:
        return self.strong_correlated or bool(self.markers & {'brand_impersonation', 'mailto_mismatch'})


@dataclass(frozen=True)
class SafetyFloorRule:
    id: str
    required_markers: frozenset[str]
    minimum_independent_families: int
    minimum_rule_score: int
    minimum_final_score: int
    classification: ThreatClassification
    reason: str


@dataclass(frozen=True)
class SafetyFloorDecision:
    applied: bool
    rule_id: str | None
    minimum_final_score: int | None
    classification_floor: ThreatClassification | None
    reason: str | None


SAFETY_FLOOR_RULES: tuple[SafetyFloorRule, ...] = (
    SafetyFloorRule(
        id='brand_impersonation_with_routing_mismatch',
        required_markers=frozenset({'brand_impersonation', 'routing_mismatch'}),
        minimum_independent_families=2,
        minimum_rule_score=80,
        minimum_final_score=82,
        classification=ThreatClassification.phishing,
        reason='Strong claimed-brand impersonation is corroborated by unsafe message routing.',
    ),
    SafetyFloorRule(
        id='brand_impersonation_authentication_sensitive_action',
        required_markers=frozenset({'brand_impersonation', 'authentication_issue', 'sensitive_action'}),
        minimum_independent_families=3,
        minimum_rule_score=75,
        minimum_final_score=82,
        classification=ThreatClassification.phishing,
        reason='A sensitive claimed-brand request is corroborated by non-passing authentication evidence.',
    ),
    SafetyFloorRule(
        id='sensitive_action_external_destination_routing',
        required_markers=frozenset({'sensitive_action', 'suspicious_destination', 'routing_mismatch'}),
        minimum_independent_families=3,
        minimum_rule_score=75,
        minimum_final_score=80,
        classification=ThreatClassification.phishing,
        reason='A sensitive action, unsafe destination, and routing mismatch form independent corroboration.',
    ),
    SafetyFloorRule(
        id='government_legal_impersonation_external_action',
        required_markers=frozenset({'government_legal_claim', 'suspicious_destination', 'routing_mismatch'}),
        minimum_independent_families=3,
        minimum_rule_score=75,
        minimum_final_score=80,
        classification=ThreatClassification.phishing,
        reason='A government or legal claim is paired with unsafe routing and an external action destination.',
    ),
    SafetyFloorRule(
        id='credential_or_payment_domain_authentication_mismatch',
        required_markers=frozenset({'sensitive_action', 'brand_impersonation', 'authentication_issue'}),
        minimum_independent_families=3,
        minimum_rule_score=75,
        minimum_final_score=80,
        classification=ThreatClassification.phishing,
        reason='A credential or payment request is corroborated by identity and authentication mismatch.',
    ),
)


def _value(source: Any, key: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _enum_value(value: Any) -> str | None:
    return getattr(value, 'value', value) if value is not None else None


def _signal_code(signal: Any) -> str:
    return str(_value(signal, 'code', ''))


def _sender_domain(parsed_email: Any) -> str | None:
    sender = _value(parsed_email, 'sender')
    address = _value(sender, 'address') if sender else None
    return str(address).rsplit('@', 1)[-1].casefold() if address and '@' in str(address) else None


def _claimed_brand(parsed_email: Any, aligned_authentication: bool):
    sender = _value(parsed_email, 'sender')
    return assess_claimed_brand(
        display_name=_value(sender, 'name') if sender else None,
        subject=_value(parsed_email, 'subject'),
        body=' '.join(filter(None, [_value(parsed_email, 'body_text', ''), _value(parsed_email, 'body_visible_text', '')])),
        sender_domain=_sender_domain(parsed_email),
        authenticated_sender=aligned_authentication,
    )


def evaluate_high_confidence_rule_evidence(signals: Iterable[ThreatSignal], parsed_email: Any = None) -> EvidenceSummary:
    """Summarize independent deterministic evidence families.

    Duplicate signals from the same family count once. Non-scoring safety
    findings can establish a floor, but never fabricate numeric contributions.
    """
    signal_list = list(signals or [])
    family_codes: dict[str, set[str]] = {family: set() for family in ('identity', 'routing', 'authentication', 'action', 'infrastructure')}
    markers: set[str] = set()
    high_codes: list[str] = []

    for signal in signal_list:
        code = _signal_code(signal)
        family: str | None = None
        if code in IDENTITY_CODES:
            family = 'identity'
            markers.add('brand_impersonation')
        elif code in ROUTING_CODES:
            family = 'routing'
            markers.add('routing_mismatch')
        elif code in AUTH_CODES:
            family = 'authentication'
            markers.add('authentication_issue')
        elif code in ACTION_CODES or code.startswith('content_') and any(token in code for token in ('credential', 'payment', 'mfa', 'account', 'banking', 'government', 'crypto', 'gift_card')):
            family = 'action'
            if code in SENSITIVE_ACTION_CODES or code.startswith('content_') and code not in {'content_urgency', 'content_impersonation'}:
                markers.add('sensitive_action')
            if code == 'mailto_destination_mismatch':
                markers.update({'mailto_mismatch', 'suspicious_destination'})
        elif code in INFRASTRUCTURE_CODES or code.startswith('url_'):
            family = 'infrastructure'
            if code in {'url_trusted_text_unrelated_destination', 'url_visible_href_mismatch', 'url_lookalike_domain', 'url_ip_host', 'url_punycode', 'url_homograph', 'url_sender_domain_mismatch'}:
                markers.add('suspicious_destination')
        if family:
            family_codes[family].add(code)
            if _enum_value(_value(signal, 'severity')) == 'high':
                high_codes.append(code)

    sender = _value(parsed_email, 'sender') if parsed_email is not None else None
    sender_address = _value(sender, 'address') if sender is not None else None
    auth = evaluate_authentication(
        _value(parsed_email, 'headers', {}) if parsed_email is not None else {},
        str(sender_address) if sender_address else None,
    )
    auth_issue = any(
        item.state in {AuthenticationState.failed, AuthenticationState.inconclusive, AuthenticationState.conflicting, AuthenticationState.malformed}
        or item.result == 'none'
        for item in auth.evidence
    )
    aligned_authentication = auth.trusted_sender
    if auth_issue:
        family_codes['authentication'].add('authentication_state')
        markers.add('authentication_issue')

    brand = _claimed_brand(parsed_email, aligned_authentication) if parsed_email is not None else None
    official_brand_domain = bool(brand and brand.sender_domain_matches)
    if official_brand_domain:
        markers.add('official_brand_domain')
    external_actionable_destination = False
    personal_mailto_destination = False
    if parsed_email is not None:
        for item in _value(parsed_email, 'url_evidence', []) or []:
            if _value(item, 'user_actionable', False) and _value(item, 'source_type') != 'tracking_pixel' and _value(item, 'external_domain') is True:
                external_actionable_destination = True
        mailto_domains = set(_value(parsed_email, 'mailto_destinations_redacted_or_normalized', []) or [])
        personal_mailto_destination = bool(mailto_domains & PERSONAL_MAILBOX_DOMAINS)
        if mailto_domains and personal_mailto_destination:
            family_codes['action'].add('mailto_destination')
            markers.add('personal_mailto_destination')
        if _value(parsed_email, 'mailto_external_domain_mismatch', False):
            family_codes['action'].add('mailto_destination_mismatch')
            markers.update({'mailto_mismatch', 'sensitive_action'})
    if external_actionable_destination:
        family_codes['action'].add('external_actionable_destination')
        markers.add('external_destination')

    if brand and brand.sensitive_claim:
        markers.add('sensitive_action')
    if any(code in GOVERNMENT_LEGAL_CODES for code in (_signal_code(signal) for signal in signal_list)):
        markers.add('government_legal_claim')
    if external_actionable_destination and any(code in INFRASTRUCTURE_CODES for code in family_codes['infrastructure']):
        markers.add('suspicious_destination')
    if personal_mailto_destination and 'mailto_destination_mismatch' in family_codes['action']:
        markers.add('suspicious_destination')

    families = tuple(family for family in ('identity', 'routing', 'authentication', 'action', 'infrastructure') if family_codes[family])
    family_code_values = {family: tuple(sorted(codes)) for family, codes in family_codes.items() if codes}
    high_relevant = tuple(sorted(set(high_codes)))
    strong = len(families) >= 3 and bool(high_relevant) and len(signal_list) > 0
    moderate = len(families) >= 2
    protective: list[str] = []
    if aligned_authentication:
        protective.append('aligned_spf_dkim_or_dmarc_pass')
    if official_brand_domain:
        protective.append('recognized_official_brand_domain')
    if not markers & {'sensitive_action'}:
        protective.append('no_sensitive_action_detected')
    if 'routing_mismatch' not in markers:
        protective.append('no_routing_mismatch_detected')
    # A pass can block a floor only when the identity, routing, and action
    # context is otherwise clean; it never erases high-severity findings.
    protective_override = bool(
        aligned_authentication and official_brand_domain
        and not markers & {'brand_impersonation', 'routing_mismatch', 'sensitive_action', 'suspicious_destination'}
        and not high_relevant
    )
    if protective_override:
        protective.append('protective_alignment_blocks_floor')

    return EvidenceSummary(
        rule_raw_score=calculate_raw_risk_score(signal_list),
        rule_adjusted_score=0,
        independent_families=families,
        family_codes=family_code_values,
        markers=frozenset(markers),
        high_severity_codes=high_relevant,
        protective_evidence=tuple(dict.fromkeys(protective)),
        strong_correlated=strong and not protective_override,
        moderate_correlated=moderate and not protective_override,
        official_brand_domain=official_brand_domain,
        aligned_authentication=aligned_authentication,
        sensitive_action='sensitive_action' in markers,
        external_actionable_destination=external_actionable_destination,
        personal_mailto_destination=personal_mailto_destination,
    )


def evaluate_safety_floor(rule_score: int, summary: EvidenceSummary) -> SafetyFloorDecision:
    """Apply the first matching semantic floor rule, if evidence is corroborated."""
    for rule in SAFETY_FLOOR_RULES:
        if rule.minimum_rule_score <= rule_score and len(summary.independent_families) >= rule.minimum_independent_families and rule.required_markers.issubset(summary.markers):
            return SafetyFloorDecision(True, rule.id, rule.minimum_final_score, rule.classification, rule.reason)
    if summary.strong_correlated and rule_score >= 80:
        return SafetyFloorDecision(
            True,
            'strong_correlated_deterministic_evidence',
            80,
            ThreatClassification.phishing,
            'Multiple independent high-concern rule families outweigh a low-probability ML disagreement.',
        )
    if summary.moderate_correlated and rule_score >= 60:
        return SafetyFloorDecision(
            True,
            'moderate_correlated_deterministic_evidence',
            60,
            ThreatClassification.suspicious,
            'Multiple independent rule families establish a moderate minimum risk that requires review.',
        )
    return SafetyFloorDecision(False, None, None, None, None)
