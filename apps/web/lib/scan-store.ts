import type { DashboardStats, ScanIndicator, ScanRecord, ThreatVector } from '@/types';
import type { AnalysisInputMode, EmailAttachmentMetadata, ThreatSeverity, UnifiedAnalysisResponse } from '@/types/analysis';
import type { PredictionResponse } from '@/types/inference';

const SCAN_STORAGE_KEY = 'phishphage.scan-records.v1';
const SCAN_STORAGE_EVENT = 'phishphage:scan-records-changed';
export const CURRENT_RULE_ENGINE_VERSION = 'rules-v3.1.0';
export const CURRENT_ML_MODEL_VERSION = '1.0.0';

const severityRank: Record<ThreatSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

function isScanIndicator(value: unknown): value is ScanIndicator {
  if (!value || typeof value !== 'object') return false;
  const indicator = value as Partial<ScanIndicator>;
  return typeof indicator.code === 'string'
    && typeof indicator.title === 'string'
    && typeof indicator.category === 'string'
    && (indicator.severity === 'low' || indicator.severity === 'medium' || indicator.severity === 'high')
    && typeof indicator.score === 'number'
    && (indicator.description === undefined || typeof indicator.description === 'string')
    && (indicator.evidence === undefined || indicator.evidence === null || typeof indicator.evidence === 'string');
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isAttachment(value: unknown) {
  if (!value || typeof value !== 'object') return false;
  const attachment = value as Record<string, unknown>;
  return (attachment.filename === null || typeof attachment.filename === 'string')
    && (attachment.content_type === null || typeof attachment.content_type === 'string')
    && typeof attachment.size_bytes === 'number'
    && (attachment.disposition === null || typeof attachment.disposition === 'string')
    && (attachment.extension === undefined || attachment.extension === null || typeof attachment.extension === 'string')
    && (attachment.suspicious_extension === undefined || typeof attachment.suspicious_extension === 'boolean');
}

function isScanDetails(value: unknown) {
  if (!value || typeof value !== 'object') return false;
  const details = value as Record<string, unknown>;
  return (details.replyTo === null || typeof details.replyTo === 'string')
    && isStringArray(details.recipients)
    && isStringArray(details.cc)
    && (details.messageDate === null || typeof details.messageDate === 'string')
    && (details.messageId === null || typeof details.messageId === 'string')
    && isStringArray(details.recommendations)
    && isStringArray(details.urls)
    && Array.isArray(details.attachments)
    && details.attachments.every(isAttachment)
    && (details.inputMode === undefined || details.inputMode === 'quick_paste' || details.inputMode === 'raw_email' || details.inputMode === 'eml_upload')
    && (details.ruleEngine === undefined || (
      typeof details.ruleEngine === 'object'
      && details.ruleEngine !== null
      && (details.ruleEngine as Record<string, unknown>).status === 'active'
      && typeof (details.ruleEngine as Record<string, unknown>).version === 'string'
    ))
    && (details.mlEngine === undefined || (
      typeof details.mlEngine === 'object'
      && details.mlEngine !== null
      && ((details.mlEngine as Record<string, unknown>).status === 'available' || (details.mlEngine as Record<string, unknown>).status === 'unavailable')
      && ((details.mlEngine as Record<string, unknown>).version === null || typeof (details.mlEngine as Record<string, unknown>).version === 'string')
    ));
}

function isScanRecord(value: unknown): value is ScanRecord {
  if (!value || typeof value !== 'object') return false;
  const scan = value as Partial<ScanRecord>;
  return typeof scan.id === 'string'
    && typeof scan.timestamp === 'string'
    && typeof scan.subject === 'string'
    && typeof scan.sender === 'string'
    && (scan.classification === 'safe' || scan.classification === 'suspicious' || scan.classification === 'phishing')
    && typeof scan.riskScore === 'number'
    && typeof scan.confidence === 'number'
    && Array.isArray(scan.indicators)
    && scan.indicators.every(isScanIndicator)
    && typeof scan.attachmentCount === 'number'
    && typeof scan.extractedUrlCount === 'number'
    && (scan.details === undefined || isScanDetails(scan.details));
}

function notifyScanChange() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(SCAN_STORAGE_EVENT));
  }
}

function createId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2)}`;
}

export function assessScanFreshness(scan: ScanRecord): { status: 'current' | 'stale'; reason: string | null } {
  if (scan.details?.analysisFreshness === 'stale') {
    return { status: 'stale', reason: scan.details.staleReason ?? 'Stored analysis is marked stale; re-scan the original email.' };
  }
  const rules = scan.details?.ruleEngine;
  const ml = scan.details?.mlEngine;
  if (!rules?.version || rules.version !== CURRENT_RULE_ENGINE_VERSION) {
    return { status: 'stale', reason: scan.details?.staleReason ?? `Rule result is not from ${CURRENT_RULE_ENGINE_VERSION}. Re-scan the original email.` };
  }
  if (ml?.status !== 'available' || ml.version !== CURRENT_ML_MODEL_VERSION) {
    return { status: 'stale', reason: scan.details?.staleReason ?? `ML result is unavailable or not from ${CURRENT_ML_MODEL_VERSION}. Re-scan with the provisioned model.` };
  }
  return { status: 'current', reason: null };
}

export function createScanRecord(result: UnifiedAnalysisResponse, inputMode?: AnalysisInputMode): ScanRecord {
  const analysisFreshness = result.analysis_freshness ?? (
    result.rule_analysis.engine_version === CURRENT_RULE_ENGINE_VERSION
      && result.ml_analysis.status === 'available'
      && result.ml_analysis.model_version === CURRENT_ML_MODEL_VERSION ? 'current' : 'stale'
  );
  return {
    id: createId(),
    timestamp: new Date().toISOString(),
    subject: result.parser.subject?.trim() || '(No subject)',
    sender: result.parser.sender?.address?.trim() || 'Not supplied',
    classification: result.decision.classification,
    riskScore: result.decision.risk_score,
    confidence: result.decision.confidence,
    indicators: result.rule_analysis.signals.map((signal) => ({
      code: signal.code,
      title: signal.title,
      category: signal.category,
      severity: signal.severity,
      score: signal.score,
      description: signal.description,
      evidence: signal.evidence,
      sourceEngine: signal.source_engine,
      evidenceType: signal.evidence_type,
      tone: signal.tone,
      contributesToScore: signal.contributes_to_score,
      provenance: signal.provenance,
    })),
    attachmentCount: result.parser.attachments.length,
    extractedUrlCount: result.parser.extracted_urls.length,
    details: {
      replyTo: result.parser.reply_to?.address ?? null,
      recipients: result.parser.recipients.map((recipient) => recipient.address),
      cc: result.parser.cc.map((recipient) => recipient.address),
      messageDate: result.parser.date,
      messageId: result.parser.message_id,
      recommendations: [...result.recommendations],
      urls: [...result.parser.extracted_urls],
      urlEvidence: (result.parser.url_evidence ?? []).map((item) => ({
        url: item.url,
        sourceType: item.source_type,
        userActionable: item.user_actionable,
        externalDomain: item.external_domain,
        securityRelevance: item.security_relevance,
      })),
      mailtoEvidence: (result.parser.mailto_evidence ?? []).map((item) => ({
        destinationDomains: [...item.destination_domains],
        recipientCount: item.recipient_count,
        visibleText: item.visible_text,
        actionType: item.action_type,
        userActionable: item.user_actionable,
        malformed: item.malformed,
      })),
      attachments: result.parser.attachments.map((attachment) => ({ ...attachment })),
      inputMode,
      ruleEngine: {
        status: 'active',
        version: result.rule_analysis.engine_version,
      },
      mlEngine: {
        status: result.ml_analysis.status,
        version: result.ml_analysis.model_version,
      },
      ruleRawScore: result.rule_raw_score ?? result.rule_analysis.risk_score,
      ruleAdjustedScore: result.rule_adjusted_score ?? result.rule_analysis.risk_score,
      mlPrediction: result.ml_prediction ?? result.ml_analysis.prediction,
      mlPhishingProbability: result.ml_phishing_probability ?? result.ml_analysis.phishing_probability,
      mlThreshold: result.ml_threshold ?? result.ml_analysis.decision_threshold ?? null,
      finalDecisionConfidence: result.final_decision_confidence ?? result.decision.confidence,
      ruleMlAgreement: result.rule_ml_agreement ?? result.engine_agreement ?? null,
      fusionReason: result.fusion_reason ?? null,
      analysisCompleteness: result.analysis_completeness?.state,
      analysisCompletenessStatus: result.analysis_completeness_status ?? result.analysis_completeness?.analysis_state,
      missingEvidence: [...(result.missing_evidence ?? result.analysis_completeness?.missing_evidence ?? [])],
      incompleteReasonCodes: [...(result.incomplete_reason_codes ?? result.analysis_completeness?.incomplete_reason_codes ?? [])],
      decisionSafetyStatus: result.decision_safety_status ?? 'needs_review',
      presentationState: result.presentation_state ?? 'needs_review',
      requiresRescan: result.requires_rescan ?? result.analysis_freshness === 'stale',
      safeVerdictAllowed: result.safe_verdict_allowed === true,
      enginesRequested: [...(result.engines_requested ?? ['rules', 'ml'])],
      enginesCompleted: [...(result.engines_completed ?? [])],
      enginesFailed: [...(result.engines_failed ?? [])],
      decisionSource: result.decision_source ?? 'unknown',
      fusionPerformed: result.fusion_performed ?? false,
      fallbackUsed: result.fallback_used ?? false,
      fallbackReason: result.fallback_reason ?? null,
      fusionPolicyVersion: result.fusion_policy_version ?? 'unknown',
      fusionInputs: result.fusion_inputs ?? {},
      fusionComponents: [...(result.fusion_components ?? [])],
      ruleWeight: result.rule_weight ?? 0.5,
      mlWeight: result.ml_weight ?? 0.5,
      safetyFloorApplied: result.safety_floor_applied ?? false,
      safetyFloorRuleId: result.safety_floor_rule_id ?? null,
      appliedFloorReason: result.applied_floor_reason ?? null,
      disagreementResolution: result.disagreement_resolution ?? null,
      preFloorScore: result.pre_floor_score ?? null,
      postFloorScore: result.post_floor_score ?? null,
      dominantEvidenceSource: result.dominant_evidence_source ?? 'unknown',
      evidenceFamilies: [...(result.evidence_families ?? [])],
      highConfidenceRuleEvidence: result.high_confidence_rule_evidence ?? false,
      protectiveEvidence: [...(result.protective_evidence ?? [])],
      positiveAuthenticationEvidence: (result.positive_authentication_evidence ?? []).map((item) => ({
        mechanism: item.mechanism,
        state: item.state,
        domain: item.domain,
        alignedWithFrom: item.aligned_with_from,
        result: item.result,
        displayLabel: item.display_label,
        detail: item.detail,
      })),
      authenticationEvidence: (result.authentication_evidence ?? []).map((item) => ({
        mechanism: item.mechanism,
        state: item.state,
        domain: item.domain,
        alignedWithFrom: item.aligned_with_from,
        result: item.result,
        displayLabel: item.display_label,
        detail: item.detail,
      })),
      authenticationEvidenceStatus: result.authentication_evidence_status ?? 'unavailable',
      linkLanguagePresent: result.link_language_present ?? result.parser.link_language_present,
      actualUrlCount: result.actual_url_count ?? result.parser.actual_url_count,
      htmlAnchorCount: result.html_anchor_count ?? result.parser.html_anchor_count,
      urlExtractionStatus: result.url_extraction_status ?? result.parser.url_extraction_status,
      urlExtractionReason: result.url_extraction_reason ?? result.parser.url_extraction_reason,
      actionableUrlCount: result.actionable_url_count ?? result.parser.actionable_url_count,
      trackingPixelCount: result.tracking_pixel_count ?? result.parser.tracking_pixel_count,
      externalTrackingPixelCount: result.external_tracking_pixel_count ?? result.parser.external_tracking_pixel_count,
      mailtoCount: result.mailto_count ?? result.parser.mailto_count,
      actionableMailtoCount: result.actionable_mailto_count ?? result.parser.actionable_mailto_count,
      mailtoDestinationsRedactedOrNormalized: [...(result.mailto_destinations_redacted_or_normalized ?? result.parser.mailto_destinations_redacted_or_normalized ?? [])],
      mailtoDomainCount: result.mailto_domain_count ?? result.parser.mailto_domain_count,
      mailtoExternalDomainMismatch: result.mailto_external_domain_mismatch ?? result.parser.mailto_external_domain_mismatch,
      mailtoPersonalProvider: result.mailto_personal_provider ?? result.parser.mailto_personal_provider,
      mailtoActionTypes: [...(result.mailto_action_types ?? result.parser.mailto_action_types ?? [])],
      mailtoActionType: result.mailto_action_type ?? result.parser.mailto_action_type,
      analysisFreshness,
      staleReason: analysisFreshness === 'current' ? null : (
        result.stale_reason ?? 'This scan was produced by an unavailable or superseded analysis engine. Re-scan the original email.'
      ),
      currentRuleVersion: result.current_rule_version ?? CURRENT_RULE_ENGINE_VERSION,
      storedRuleVersion: result.stored_rule_version ?? result.rule_analysis.engine_version,
    },
  };
}

function headerValue(rawEmail: string, name: string) {
  const match = rawEmail.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'));
  return match?.[1]?.trim() || '';
}

export function createProductionScanRecord(
  result: PredictionResponse,
  rawEmail: string,
  inputMode: AnalysisInputMode,
  attachments: EmailAttachmentMetadata[] = [],
): ScanRecord {
  const subject = headerValue(rawEmail, 'Subject') || '(No subject)';
  const sender = headerValue(rawEmail, 'From') || 'Not supplied';
  const rawClassification = (result.final_classification ?? (result.prediction === 'phishing' ? 'phishing' : result.probability >= 0.35 ? 'suspicious' : 'safe')) as 'safe' | 'suspicious' | 'phishing';
  const signalValues = [
    ...result.signals.detected_indicators,
    ...result.signals.phishing_signals,
    ...result.signals.authentication_signals,
    ...result.signals.url_indicators,
    ...result.signals.urgency_indicators,
  ];
  const modelIndicators = [...new Set(signalValues)].map((value, index) => ({
    code: `production-${value.toLowerCase().replace(/[^a-z0-9]+/g, '-') || index}`,
    title: value.replaceAll('_', ' '),
    category: 'model signal',
    severity: value === 'display_destination_mismatch' ? 'high' as ThreatSeverity : value === 'actionable_url' || value === 'click' ? 'medium' as ThreatSeverity : 'low' as ThreatSeverity,
    score: 0,
    description: value === 'actionable_url' || value === 'click'
      ? 'The message asks the recipient to interact with a link or click-oriented action.'
      : 'Signal returned by the approved production model; no numeric contribution is fabricated here.',
    evidence: null,
    sourceEngine: 'ml',
    evidenceType: 'model_signal',
    tone: value === 'actionable_url' || value === 'click' ? 'review' : 'informational',
    contributesToScore: false,
  }));
  const ruleIndicators = (result.rule_findings ?? []).map((signal) => ({
    code: signal.code,
    title: signal.mapped_title ?? signal.title,
    category: signal.category,
    severity: signal.severity,
    score: signal.score,
    description: signal.mapped_description ?? signal.description,
    evidence: signal.evidence,
    sourceEngine: signal.source_engine,
    evidenceType: signal.evidence_type,
    tone: signal.tone,
    contributesToScore: signal.contributes_to_score,
    provenance: signal.provenance,
  }));
  const indicators = [...ruleIndicators, ...modelIndicators.filter((model) => !ruleIndicators.some((rule) => rule.code === model.code))];
  const analysisFreshness = result.analysis_freshness === 'current' && result.current_rule_version === CURRENT_RULE_ENGINE_VERSION && result.model_version === CURRENT_ML_MODEL_VERSION ? 'current' : 'stale';
  const safeAllowed = result.safe_verdict_allowed === true && result.fusion_policy_version === 'asymmetric-safety-v1' && analysisFreshness === 'current';
  return {
    id: createId(), timestamp: new Date().toISOString(), subject, sender, classification: rawClassification,
    riskScore: Math.round(result.final_risk_score ?? result.risk_score), confidence: result.final_decision_confidence ?? result.confidence, indicators,
    attachmentCount: attachments.length, extractedUrlCount: result.signals.url_indicators.length,
    details: {
      replyTo: null, recipients: [], cc: [], messageDate: null, messageId: null,
      recommendations: [...result.recommendations], attachments: attachments.map((item) => ({ ...item })), inputMode,
      ruleEngine: { status: 'active', version: result.stored_rule_version ?? 'unknown' },
      mlEngine: { status: 'available', version: result.model_version },
      mlPrediction: result.prediction, mlPhishingProbability: result.probability,
      mlThreshold: result.threshold_used, finalDecisionConfidence: result.final_decision_confidence ?? result.confidence,
      ruleRawScore: result.rule_raw_score ?? null,
      ruleAdjustedScore: result.rule_adjusted_score ?? null,
      ruleMlAgreement: result.rule_ml_agreement ?? null,
      fusionReason: result.fusion_reason ?? null,
      fusionPolicyVersion: result.fusion_policy_version ?? 'unknown',
      fusionInputs: result.fusion_inputs ?? {},
      fusionComponents: [...(result.fusion_components ?? [])],
      ruleWeight: result.rule_weight ?? 0.5,
      mlWeight: result.ml_weight ?? 0.5,
      safetyFloorApplied: result.safety_floor_applied ?? false,
      safetyFloorRuleId: result.safety_floor_rule_id ?? null,
      appliedFloorReason: result.applied_floor_reason ?? null,
      disagreementResolution: result.disagreement_resolution ?? null,
      preFloorScore: result.pre_floor_score ?? null,
      postFloorScore: result.post_floor_score ?? null,
      dominantEvidenceSource: result.dominant_evidence_source ?? 'unknown',
      evidenceFamilies: [...(result.evidence_families ?? [])],
      highConfidenceRuleEvidence: result.high_confidence_rule_evidence ?? false,
      protectiveEvidence: [...(result.protective_evidence ?? [])],
      analysisCompleteness: result.analysis_completeness?.state,
      analysisCompletenessStatus: result.analysis_completeness_status ?? 'unavailable',
      missingEvidence: [...(result.missing_evidence ?? [])],
      incompleteReasonCodes: [...(result.incomplete_reason_codes ?? [])],
      decisionSafetyStatus: result.decision_safety_status ?? 'needs_review',
      presentationState: result.presentation_state ?? 'needs_review',
      requiresRescan: result.requires_rescan ?? !safeAllowed,
      safeVerdictAllowed: safeAllowed,
      enginesRequested: [...(result.engines_requested ?? ['rules', 'ml'])],
      enginesCompleted: [...(result.engines_completed ?? [])],
      enginesFailed: [...(result.engines_failed ?? [])],
      decisionSource: result.decision_source ?? 'unknown',
      fusionPerformed: result.fusion_performed ?? false,
      fallbackUsed: result.fallback_used ?? false,
      fallbackReason: result.fallback_reason ?? null,
      authenticationEvidenceStatus: result.authentication_evidence_status ?? 'unavailable',
      positiveAuthenticationEvidence: (result.positive_authentication_evidence ?? []).map((item) => ({
        mechanism: String(item.mechanism ?? ''), state: String(item.state ?? 'unavailable'), domain: typeof item.domain === 'string' ? item.domain : null, alignedWithFrom: typeof item.aligned_with_from === 'boolean' ? item.aligned_with_from : null, result: typeof item.result === 'string' ? item.result : null, displayLabel: typeof item.display_label === 'string' ? item.display_label : undefined, detail: typeof item.detail === 'string' ? item.detail : null,
      })),
      authenticationEvidence: (result.authentication_evidence ?? []).map((item) => ({
        mechanism: item.mechanism,
        state: item.state,
        domain: item.domain,
        alignedWithFrom: item.aligned_with_from,
        result: item.result,
        displayLabel: item.display_label,
        detail: item.detail,
      })),
      urls: [...(result.extracted_urls ?? [])],
      urlEvidence: (result.url_evidence ?? []).map((item) => ({ url: item.url, sourceType: item.source_type, userActionable: item.user_actionable, externalDomain: item.external_domain, securityRelevance: item.security_relevance })),
      actionableUrlCount: result.actionable_url_count ?? 0,
      trackingPixelCount: result.tracking_pixel_count ?? 0,
      externalTrackingPixelCount: result.external_tracking_pixel_count ?? 0,
      mailtoCount: result.mailto_count ?? 0,
      actionableMailtoCount: result.actionable_mailto_count ?? 0,
      mailtoDestinationsRedactedOrNormalized: [...(result.mailto_destinations_redacted_or_normalized ?? [])],
      mailtoDomainCount: result.mailto_domain_count ?? 0,
      mailtoExternalDomainMismatch: result.mailto_external_domain_mismatch ?? false,
      mailtoPersonalProvider: result.mailto_personal_provider ?? false,
      mailtoActionTypes: [...(result.mailto_action_types ?? [])],
      mailtoActionType: result.mailto_action_type ?? 'unknown',
      linkLanguagePresent: result.link_language_present ?? false,
      actualUrlCount: result.actual_url_count ?? result.extracted_urls?.length ?? 0,
      htmlAnchorCount: result.html_anchor_count ?? 0,
      urlExtractionStatus: result.url_extraction_status ?? 'unavailable',
      urlExtractionReason: result.url_extraction_reason ?? null,
      analysisFreshness,
      staleReason: analysisFreshness === 'current' ? null : (result.stale_reason ?? 'Engine-version metadata was not current; re-scan the original email.'),
      currentRuleVersion: result.current_rule_version ?? CURRENT_RULE_ENGINE_VERSION,
      storedRuleVersion: result.stored_rule_version ?? null,
    },
  };
}

export function readScans(): ScanRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const stored = window.localStorage.getItem(SCAN_STORAGE_KEY);
    if (!stored) return [];
    const parsed: unknown = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(isScanRecord)
      .map((scan) => {
        const freshness = assessScanFreshness(scan);
        const legacySafety = scan.details?.safeVerdictAllowed === undefined;
        const completenessStatus = scan.details?.analysisCompletenessStatus ?? (legacySafety ? 'unavailable' : 'partial');
        const policyKnown = scan.details?.fusionPolicyVersion === 'asymmetric-safety-v1';
        const safeAllowed = scan.details?.safeVerdictAllowed === true && policyKnown && freshness.status === 'current' && completenessStatus !== 'partial' && completenessStatus !== 'incomplete' && completenessStatus !== 'unavailable' && completenessStatus !== 'stale';
        return {
          ...scan,
          // Preserve the original classification; presentation state below
          // carries the conservative migration status without inventing a new floor.
          details: scan.details ? {
            ...scan.details,
            fusionPolicyVersion: scan.details.fusionPolicyVersion ?? 'unknown',
            analysisFreshness: freshness.status,
            staleReason: freshness.status === 'stale' ? freshness.reason : null,
            analysisCompletenessStatus: completenessStatus,
            decisionSafetyStatus: scan.details.decisionSafetyStatus ?? (freshness.status === 'stale' ? 'rescan_required' : 'unable_to_verify'),
            presentationState: freshness.status === 'stale' ? 'rescan_required' : safeAllowed ? scan.classification : 'needs_review',
            requiresRescan: scan.details.requiresRescan ?? (freshness.status === 'stale' || !policyKnown),
            safeVerdictAllowed: safeAllowed,
          } : scan.details,
        };
      })
      .sort((left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime());
  } catch {
    return [];
  }
}

export function scanPresentationState(scan: ScanRecord): string {
  if (scan.details?.analysisFreshness === 'stale') return 'Re-scan required';
  if (scan.details?.safeVerdictAllowed !== true) return 'Needs review';
  return scan.classification;
}

export function saveScan(scan: ScanRecord): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const scans = [scan, ...readScans().filter((stored) => stored.id !== scan.id)];
    window.localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(scans));
    notifyScanChange();
    return true;
  } catch {
    return false;
  }
}

export function deleteScans(ids: Iterable<string>): number {
  if (typeof window === 'undefined') return 0;
  const selectedIds = new Set(ids);
  if (selectedIds.size === 0) return 0;

  try {
    const scans = readScans();
    const remaining = scans.filter((scan) => !selectedIds.has(scan.id));
    const deletedCount = scans.length - remaining.length;
    if (deletedCount === 0) return 0;
    window.localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(remaining));
    notifyScanChange();
    return deletedCount;
  } catch {
    return 0;
  }
}

export function deleteScan(id: string): boolean {
  return deleteScans([id]) === 1;
}

export function clearScans(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    window.localStorage.removeItem(SCAN_STORAGE_KEY);
    notifyScanChange();
    return true;
  } catch {
    return false;
  }
}

export function subscribeToScans(listener: () => void): () => void {
  if (typeof window === 'undefined') return () => undefined;

  const handleStorage = (event: StorageEvent) => {
    if (event.key === SCAN_STORAGE_KEY) listener();
  };
  window.addEventListener(SCAN_STORAGE_EVENT, listener);
  window.addEventListener('storage', handleStorage);

  return () => {
    window.removeEventListener(SCAN_STORAGE_EVENT, listener);
    window.removeEventListener('storage', handleStorage);
  };
}

export function calculateDashboardStats(scans: ScanRecord[]): DashboardStats {
  const totalScans = scans.length;
  const safeEmails = scans.filter((scan) => scan.classification === 'safe').length;
  const suspiciousEmails = scans.filter((scan) => scan.classification === 'suspicious').length;
  const phishingDetected = scans.filter((scan) => scan.classification === 'phishing').length;
  const averageRiskScore = totalScans
    ? Math.round(scans.reduce((sum, scan) => sum + scan.riskScore, 0) / totalScans)
    : 0;

  return { totalScans, safeEmails, suspiciousEmails, phishingDetected, averageRiskScore };
}

export function calculateThreatVectors(scans: ScanRecord[]): ThreatVector[] {
  const frequencies = new Map<string, ThreatVector>();

  for (const indicator of scans.flatMap((scan) => scan.indicators)) {
    if (indicator.score <= 0) continue;
    const existing = frequencies.get(indicator.code);
    if (!existing) {
      frequencies.set(indicator.code, { label: indicator.title, count: 1, severity: indicator.severity });
      continue;
    }
    existing.count += 1;
    if (severityRank[indicator.severity] > severityRank[existing.severity]) {
      existing.severity = indicator.severity;
    }
  }

  return [...frequencies.values()].sort((left, right) => (
    right.count - left.count
    || severityRank[right.severity] - severityRank[left.severity]
    || left.label.localeCompare(right.label)
  ));
}
