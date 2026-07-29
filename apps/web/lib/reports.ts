import type { ScanRecord } from '@/types';
import type { ScanReportData } from '@/types/reports';

export type ReportExportFormat = 'json' | 'csv';

export const LARGE_BATCH_EXPORT_THRESHOLD = 10;
export const REPORT_PRIVACY_DISCLAIMER = 'This report contains analysis metadata and findings only. Raw email bodies and full raw headers are excluded. Reports are generated in browser memory and are not stored by PhishShield AI.';

export function formatReportInputMode(inputMode: ScanReportData['input_mode']) {
  if (inputMode === 'quick_paste') return 'Quick Paste';
  if (inputMode === 'raw_email') return 'Raw Email';
  if (inputMode === 'eml_upload') return '.eml Upload';
  return 'Not recorded';
}

export function formatReportDate(timestamp: string) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'long' }).format(date);
}

function timestampSlug(timestamp: string) {
  return timestamp.replace(/\.\d{3}Z$/, 'Z').replaceAll(':', '-');
}

function subjectSlug(subject: string) {
  const slug = subject.toLocaleLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
  return slug || 'untitled-scan';
}

function csvValue(value: string | number | boolean) {
  let text = String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function escapeHtml(value: string | number | boolean | null) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character] ?? character);
}

function printableList(items: string[], emptyMessage: string) {
  if (items.length === 0) return `<p class="muted">${escapeHtml(emptyMessage)}</p>`;
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

export function createScanReport(scan: ScanRecord, generatedAt = new Date().toISOString()): ScanReportData {
  const details = scan.details;
  const analysisFreshness = details?.analysisFreshness ?? 'stale';
  const staleReason = analysisFreshness === 'current'
    ? null
    : details?.staleReason || 'Engine-version metadata was not recorded; re-scan the original email.';
  const safeAllowed = details?.safeVerdictAllowed === true && details?.fusionPolicyVersion === 'asymmetric-safety-v1' && analysisFreshness === 'current';
  return {
    report_schema_version: '1.3',
    product: 'PhishShield AI',
    report_generated_at: generatedAt,
    scan_id: scan.id,
    scan_timestamp: scan.timestamp,
    subject: scan.subject,
    sender: scan.sender,
    recipients: details?.recipients ?? [],
    input_mode: details?.inputMode ?? 'not_recorded',
    final_classification: scan.classification,
    risk_score: scan.riskScore,
    confidence: scan.confidence,
    final_decision_confidence: details?.finalDecisionConfidence ?? null,
    rule_raw_score: details?.ruleRawScore ?? null,
    rule_adjusted_score: details?.ruleAdjustedScore ?? null,
    ml_prediction: details?.mlPrediction ?? null,
    ml_phishing_probability: details?.mlPhishingProbability ?? null,
    ml_threshold: details?.mlThreshold ?? null,
    rule_ml_agreement: details?.ruleMlAgreement ?? null,
    fusion_reason: details?.fusionReason ?? null,
    analysis_completeness: details?.analysisCompleteness ?? 'not_recorded',
    analysis_completeness_status: (details?.analysisCompletenessStatus ?? 'not_recorded') as ScanReportData['analysis_completeness_status'],
    missing_evidence: details?.missingEvidence ?? [],
    incomplete_reason_codes: details?.incompleteReasonCodes ?? [],
    decision_safety_status: details?.decisionSafetyStatus ?? 'unable_to_verify',
    presentation_state: details?.presentationState ?? 'needs_review',
    requires_rescan: details?.requiresRescan ?? analysisFreshness === 'stale',
    safe_verdict_allowed: safeAllowed,
    engines_requested: details?.enginesRequested ?? ['rules', 'ml'],
    engines_completed: details?.enginesCompleted ?? [],
    engines_failed: details?.enginesFailed ?? [],
    decision_source: details?.decisionSource ?? 'unknown',
    fusion_performed: details?.fusionPerformed ?? false,
    fallback_used: details?.fallbackUsed ?? false,
    fallback_reason: details?.fallbackReason ?? null,
    fusion_policy_version: details?.fusionPolicyVersion ?? 'unknown',
    fusion_inputs: details?.fusionInputs ?? {},
    fusion_components: details?.fusionComponents ?? [],
    rule_weight: details?.ruleWeight ?? 0.5,
    ml_weight: details?.mlWeight ?? 0.5,
    safety_floor_applied: details?.safetyFloorApplied ?? false,
    safety_floor_rule_id: details?.safetyFloorRuleId ?? null,
    applied_floor_reason: details?.appliedFloorReason ?? null,
    disagreement_resolution: details?.disagreementResolution ?? null,
    pre_floor_score: details?.preFloorScore ?? null,
    post_floor_score: details?.postFloorScore ?? null,
    dominant_evidence_source: details?.dominantEvidenceSource ?? 'unknown',
    evidence_families: details?.evidenceFamilies ?? [],
    high_confidence_rule_evidence: details?.highConfidenceRuleEvidence ?? false,
    protective_evidence: details?.protectiveEvidence ?? [],
    positive_authentication_evidence: (details?.positiveAuthenticationEvidence ?? []).map((item) => ({
      mechanism: item.mechanism,
      state: item.state,
      domain: item.domain,
      aligned_with_from: item.alignedWithFrom,
      result: item.result,
      display_label: item.displayLabel,
      detail: item.detail,
    })),
    authentication_evidence: (details?.authenticationEvidence ?? []).map((item) => ({
      mechanism: item.mechanism,
      state: item.state,
      domain: item.domain,
      aligned_with_from: item.alignedWithFrom,
      result: item.result,
      display_label: item.displayLabel,
      detail: item.detail,
    })),
    authentication_evidence_status: (details?.authenticationEvidenceStatus ?? 'unavailable') as ScanReportData['authentication_evidence_status'],
    url_evidence: (details?.urlEvidence ?? []).map((item) => ({
      url: item.url,
      source_type: item.sourceType,
      user_actionable: item.userActionable,
      external_domain: item.externalDomain,
      security_relevance: item.securityRelevance,
    })),
    analysis_freshness: analysisFreshness,
    stale_reason: staleReason,
    link_language_present: details?.linkLanguagePresent ?? false,
    actual_url_count: details?.actualUrlCount ?? details?.urls?.length ?? 0,
    html_anchor_count: details?.htmlAnchorCount ?? 0,
    url_extraction_status: details?.urlExtractionStatus ?? 'unavailable',
    url_extraction_reason: details?.urlExtractionReason ?? null,
    actionable_url_count: details?.actionableUrlCount ?? 0,
    tracking_pixel_count: details?.trackingPixelCount ?? 0,
    external_tracking_pixel_count: details?.externalTrackingPixelCount ?? 0,
    mailto_count: details?.mailtoCount ?? 0,
    actionable_mailto_count: details?.actionableMailtoCount ?? 0,
    mailto_destinations_redacted_or_normalized: details?.mailtoDestinationsRedactedOrNormalized ?? [],
    mailto_domain_count: details?.mailtoDomainCount ?? 0,
    mailto_external_domain_mismatch: details?.mailtoExternalDomainMismatch ?? false,
    mailto_personal_provider: details?.mailtoPersonalProvider ?? false,
    mailto_action_types: details?.mailtoActionTypes ?? [],
    mailto_action_type: details?.mailtoActionType ?? 'unknown',
    rule_engine: {
      status: details?.ruleEngine?.status ?? 'unknown',
      version: details?.ruleEngine?.version ?? null,
    },
    ml_engine: {
      status: details?.mlEngine?.status ?? 'unknown',
      version: details?.mlEngine?.version ?? null,
    },
    detected_indicators: scan.indicators.map((indicator) => ({
      code: indicator.code,
      title: indicator.title,
      category: indicator.category,
      severity: indicator.severity,
      score: indicator.score,
      description: indicator.description ?? null,
      evidence: indicator.evidence ?? null,
      source_engine: indicator.sourceEngine,
      evidence_type: indicator.evidenceType,
      tone: indicator.tone,
      contributes_to_score: indicator.contributesToScore,
      provenance: indicator.provenance,
    })),
    recommendations: details?.recommendations ?? [],
    extracted_urls: details?.urls ?? [],
    attachments: details?.attachments ?? [],
    privacy_disclaimer: REPORT_PRIVACY_DISCLAIMER,
  };
}

export function serializeReportsToJson(scans: ScanRecord[], generatedAt = new Date().toISOString()) {
  const reports = scans.map((scan) => createScanReport(scan, generatedAt));
  const payload = reports.length === 1
    ? reports[0]
    : { product: 'PhishShield AI', report_generated_at: generatedAt, report_count: reports.length, reports };
  return JSON.stringify(payload, null, 2);
}

export function serializeReportsToCsv(scans: ScanRecord[], generatedAt = new Date().toISOString()) {
  const columns = [
    'report_generated_at', 'scan_timestamp', 'scan_id', 'subject', 'sender', 'recipients', 'input_mode', 'final_classification',
    'risk_score', 'confidence_percent', 'presentation_state', 'safe_verdict_allowed', 'analysis_freshness', 'stale_reason', 'analysis_completeness_status', 'missing_evidence', 'decision_safety_status', 'fusion_policy_version', 'pre_floor_score', 'post_floor_score', 'safety_floor_rule_id', 'dominant_evidence_source', 'evidence_families', 'rule_engine_status', 'rule_engine_version', 'ml_engine_status', 'ml_engine_version',
    'indicator_count', 'detected_indicators', 'evidence', 'recommendations', 'extracted_urls', 'actionable_url_count', 'tracking_pixel_count', 'mailto_count', 'actionable_mailto_count', 'mailto_domains', 'attachment_count', 'attachment_metadata', 'privacy_disclaimer',
  ];
  const rows = scans.map((scan) => {
    const report = createScanReport(scan, generatedAt);
    const attachments = report.attachments.map((attachment) => `${attachment.filename ?? 'Unnamed'} (${attachment.content_type ?? 'Unknown'}, ${attachment.size_bytes} bytes)`).join(' | ');
    return [
      report.report_generated_at,
      report.scan_timestamp,
      report.scan_id,
      report.subject,
      report.sender,
      report.recipients.join(' | '),
      report.input_mode,
      report.final_classification,
      report.risk_score,
      Math.round(report.confidence * 100),
      report.presentation_state,
      report.safe_verdict_allowed,
      report.analysis_freshness,
      report.stale_reason ?? '',
      report.analysis_completeness_status,
      report.missing_evidence.join(' | '),
      report.decision_safety_status,
      report.fusion_policy_version,
      report.pre_floor_score ?? '',
      report.post_floor_score ?? '',
      report.safety_floor_rule_id ?? '',
      report.dominant_evidence_source,
      report.evidence_families.join(' | '),
      report.rule_engine.status,
      report.rule_engine.version ?? '',
      report.ml_engine.status,
      report.ml_engine.version ?? '',
      report.detected_indicators.length,
      report.detected_indicators.map((indicator) => `${indicator.title} [${indicator.severity}, +${indicator.score}]`).join(' | '),
      report.detected_indicators.map((indicator) => indicator.evidence ?? '').filter(Boolean).join(' | '),
      report.recommendations.join(' | '),
      report.extracted_urls.join(' | '),
      report.actionable_url_count,
      report.tracking_pixel_count,
      report.mailto_count,
      report.actionable_mailto_count,
      report.mailto_destinations_redacted_or_normalized.join(' | '),
      report.attachments.length,
      attachments,
      report.privacy_disclaimer,
    ].map(csvValue).join(',');
  });
  return [columns.map(csvValue).join(','), ...rows].join('\r\n');
}

export function createReportFilename(scans: ScanRecord[], format: ReportExportFormat, generatedAt = new Date().toISOString()) {
  const scope = scans.length === 1 ? subjectSlug(scans[0].subject) : `${scans.length}-scans`;
  return `phishphage-report-${scope}-${timestampSlug(generatedAt)}.${format}`;
}

export function requiresLargeBatchConfirmation(scanCount: number) {
  return scanCount >= LARGE_BATCH_EXPORT_THRESHOLD;
}

export function downloadReports(scans: ScanRecord[], format: ReportExportFormat) {
  if (typeof window === 'undefined' || scans.length === 0) return false;
  const generatedAt = new Date().toISOString();
  const content = format === 'json' ? serializeReportsToJson(scans, generatedAt) : serializeReportsToCsv(scans, generatedAt);
  const blob = new Blob([content], { type: format === 'json' ? 'application/json;charset=utf-8' : 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = createReportFilename(scans, format, generatedAt);
  anchor.click();
  URL.revokeObjectURL(url);
  return true;
}

export function createPrintableReportHtml(scan: ScanRecord, generatedAt = new Date().toISOString()) {
  const report = createScanReport(scan, generatedAt);
  const indicators = report.detected_indicators.length
    ? `<table><thead><tr><th>Indicator</th><th>Category</th><th>Severity</th><th>Score</th><th>Evidence</th></tr></thead><tbody>${report.detected_indicators.map((indicator) => `<tr><td><strong>${escapeHtml(indicator.title)}</strong><br><span class="muted">${escapeHtml(indicator.description)}</span></td><td>${escapeHtml(indicator.category)}</td><td>${escapeHtml(indicator.severity)}</td><td>+${escapeHtml(indicator.score)}</td><td>${escapeHtml(indicator.evidence || 'Pattern-based detection')}</td></tr>`).join('')}</tbody></table>`
    : '<p class="muted">No indicators detected.</p>';
  const attachments = report.attachments.length
    ? `<table><thead><tr><th>Filename</th><th>Content type</th><th>Size</th><th>Disposition</th></tr></thead><tbody>${report.attachments.map((attachment) => `<tr><td>${escapeHtml(attachment.filename || 'Unnamed')}</td><td>${escapeHtml(attachment.content_type || 'Unknown')}</td><td>${escapeHtml(attachment.size_bytes)} bytes</td><td>${escapeHtml(attachment.disposition || 'Not recorded')}</td></tr>`).join('')}</tbody></table>`
    : '<p class="muted">No attachment metadata recorded.</p>';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PhishShield AI Report - ${escapeHtml(report.subject)}</title><style>
    @page { size: auto; margin: 16mm; }
    * { box-sizing: border-box; }
    body { margin: 0; color: #0f172a; background: #fff; font: 13px/1.5 Arial, Helvetica, sans-serif; }
    header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 3px solid #2563eb; padding-bottom: 16px; margin-bottom: 24px; break-inside: avoid; }
    h1 { margin: 0; font-size: 24px; } h2 { margin: 0 0 12px; font-size: 16px; break-after: avoid; page-break-after: avoid; } p { margin: 4px 0; orphans: 3; widows: 3; }
    .brand { color: #1d4ed8; font-weight: 700; letter-spacing: .02em; } .muted { color: #64748b; }
    .verdict { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }
    .metric { border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; } .metric strong { display: block; margin-top: 4px; font-size: 18px; text-transform: capitalize; }
    .section { break-inside: avoid; page-break-inside: avoid; margin: 0 0 20px; }
    .section.allow-break { break-inside: auto; page-break-inside: auto; }
    .metadata { display: grid; grid-template-columns: 150px 1fr; border-top: 1px solid #e2e8f0; }
    .metadata dt, .metadata dd { margin: 0; padding: 7px 0; border-bottom: 1px solid #e2e8f0; } .metadata dt { color: #64748b; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; } thead { display: table-header-group; } tr { break-inside: avoid; page-break-inside: avoid; } th, td { border: 1px solid #cbd5e1; padding: 7px; text-align: left; vertical-align: top; overflow-wrap: anywhere; } th { background: #f1f5f9; }
    ul { margin: 6px 0; padding-left: 20px; } li { break-inside: avoid; } .privacy { border: 1px solid #94a3b8; background: #f8fafc; padding: 12px; font-size: 11px; break-inside: avoid; }
    @media print { body { color: #000; background: #fff; } a { color: #000; text-decoration: none; } .section.allow-break { break-inside: auto; } }
  </style></head><body>
    <header><div><div class="brand">PhishShield AI</div><h1>Email Analysis Report</h1></div><div><p><strong>Report generated</strong></p><p>${escapeHtml(formatReportDate(report.report_generated_at))}</p></div></header>
    <section class="verdict"><div class="metric"><span class="muted">Presentation state</span><strong>${escapeHtml(report.presentation_state)}</strong></div><div class="metric"><span class="muted">Risk score</span><strong>${escapeHtml(report.risk_score)}/100</strong></div><div class="metric"><span class="muted">Confidence</span><strong>${escapeHtml(Math.round(report.confidence * 100))}%</strong></div></section>
    ${report.analysis_freshness === 'stale' || !report.safe_verdict_allowed ? `<section class="section"><div class="privacy"><strong>${escapeHtml(report.presentation_state === 'rescan_required' ? 'Re-scan required' : 'Needs review')}</strong><p>${escapeHtml(report.stale_reason || report.missing_evidence.join(', ') || 'The evidence does not support a confident safe presentation.')}</p></div></section>` : ''}
    <section class="section"><h2>Email and scan metadata</h2><dl class="metadata"><dt>Scan timestamp</dt><dd>${escapeHtml(formatReportDate(report.scan_timestamp))}</dd><dt>Subject</dt><dd>${escapeHtml(report.subject)}</dd><dt>Sender</dt><dd>${escapeHtml(report.sender)}</dd><dt>Recipients</dt><dd>${escapeHtml(report.recipients.join(', ') || 'Not recorded')}</dd><dt>Input mode</dt><dd>${escapeHtml(formatReportInputMode(report.input_mode))}</dd></dl></section>
    <section class="section allow-break"><h2>Detected indicators</h2>${indicators}</section>
    <section class="section"><h2>Destinations and tracking</h2>${printableList(report.extracted_urls, 'No user-visible HTTP URLs recorded.')}<p class="muted">Actionable HTTP URLs: ${escapeHtml(report.actionable_url_count)} · External tracking pixels: ${escapeHtml(report.external_tracking_pixel_count)} · Mailto actions: ${escapeHtml(report.actionable_mailto_count)}</p><p class="muted">Mailto destination domains: ${escapeHtml(report.mailto_destinations_redacted_or_normalized.join(', ') || 'None recorded')}</p></section>
    <section class="section allow-break"><h2>Attachment metadata</h2>${attachments}</section>
    <section class="section"><h2>Recommendations</h2>${printableList(report.recommendations, 'No recommendations recorded.')}</section>
    <section class="section"><h2>Decision fusion details</h2><dl class="metadata"><dt>Fusion policy</dt><dd>${escapeHtml(report.fusion_policy_version)}</dd><dt>Raw rule score</dt><dd>${escapeHtml(report.rule_raw_score ?? 'Not recorded')} / adjusted ${escapeHtml(report.rule_adjusted_score ?? 'Not recorded')}</dd><dt>Raw ML probability</dt><dd>${escapeHtml(report.ml_phishing_probability ?? 'Not recorded')} / threshold ${escapeHtml(report.ml_threshold ?? 'Not recorded')}</dd><dt>Pre-floor / post-floor</dt><dd>${escapeHtml(report.pre_floor_score ?? 'Not recorded')} / ${escapeHtml(report.post_floor_score ?? report.risk_score)}</dd><dt>Safety floor</dt><dd>${escapeHtml(report.safety_floor_rule_id || 'None applied')} / ${escapeHtml(report.applied_floor_reason || 'No floor reason recorded')}</dd><dt>Evidence families</dt><dd>${escapeHtml(report.evidence_families.join(', ') || 'None recorded')}</dd><dt>Authentication</dt><dd>${escapeHtml(report.authentication_evidence.map((item) => `${item.mechanism}: ${item.display_label || item.state}`).join('; ') || report.authentication_evidence_status)}</dd></dl></section>
    <section class="section"><h2>Engine metadata</h2><dl class="metadata"><dt>Rule engine</dt><dd>${escapeHtml(report.rule_engine.status)} · ${escapeHtml(report.rule_engine.version || 'Version not recorded')}</dd><dt>ML engine</dt><dd>${escapeHtml(report.ml_engine.status)} · ${escapeHtml(report.ml_engine.version || 'Version not recorded')}</dd><dt>Decision safety</dt><dd>${escapeHtml(report.decision_safety_status)} · safe verdict allowed: ${escapeHtml(report.safe_verdict_allowed)}</dd><dt>Report schema</dt><dd>${escapeHtml(report.report_schema_version)}</dd><dt>Scan ID</dt><dd>${escapeHtml(report.scan_id)}</dd></dl></section>
    <footer class="privacy"><strong>Privacy notice:</strong> ${escapeHtml(report.privacy_disclaimer)}</footer>
  </body></html>`;
}

export function printScanReport(scan: ScanRecord) {
  if (typeof window === 'undefined') return false;
  const printWindow = window.open('', '_blank');
  if (!printWindow) return false;
  printWindow.opener = null;
  printWindow.document.open();
  printWindow.document.write(createPrintableReportHtml(scan));
  printWindow.document.close();
  printWindow.focus();
  window.setTimeout(() => printWindow.print(), 150);
  return true;
}
