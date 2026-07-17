import type { ScanRecord } from '@/types';
import type { ScanReportData } from '@/types/reports';

export type ReportExportFormat = 'json' | 'csv';

export const LARGE_BATCH_EXPORT_THRESHOLD = 10;
export const REPORT_PRIVACY_DISCLAIMER = 'This report contains analysis metadata and findings only. Raw email bodies and full raw headers are excluded. Reports are generated in browser memory and are not stored by PhishPhage AI.';

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

function csvValue(value: string | number) {
  let text = String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function escapeHtml(value: string | number | null) {
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
  return {
    report_schema_version: '1.1',
    product: 'PhishPhage AI',
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
    positive_authentication_evidence: (details?.positiveAuthenticationEvidence ?? []).map((item) => ({
      mechanism: item.mechanism,
      state: item.state,
      domain: item.domain,
      aligned_with_from: item.alignedWithFrom,
    })),
    authentication_evidence_status: details?.authenticationEvidenceStatus ?? 'unavailable',
    url_evidence: (details?.urlEvidence ?? []).map((item) => ({
      url: item.url,
      source_type: item.sourceType,
      user_actionable: item.userActionable,
    })),
    analysis_freshness: analysisFreshness,
    stale_reason: staleReason,
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
    : { product: 'PhishPhage AI', report_generated_at: generatedAt, report_count: reports.length, reports };
  return JSON.stringify(payload, null, 2);
}

export function serializeReportsToCsv(scans: ScanRecord[], generatedAt = new Date().toISOString()) {
  const columns = [
    'report_generated_at', 'scan_timestamp', 'scan_id', 'subject', 'sender', 'recipients', 'input_mode', 'final_classification',
    'risk_score', 'confidence_percent', 'rule_engine_status', 'rule_engine_version', 'ml_engine_status', 'ml_engine_version',
    'indicator_count', 'detected_indicators', 'evidence', 'recommendations', 'extracted_urls', 'attachment_count', 'attachment_metadata', 'privacy_disclaimer',
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
      report.rule_engine.status,
      report.rule_engine.version ?? '',
      report.ml_engine.status,
      report.ml_engine.version ?? '',
      report.detected_indicators.length,
      report.detected_indicators.map((indicator) => `${indicator.title} [${indicator.severity}, +${indicator.score}]`).join(' | '),
      report.detected_indicators.map((indicator) => indicator.evidence ?? '').filter(Boolean).join(' | '),
      report.recommendations.join(' | '),
      report.extracted_urls.join(' | '),
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

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PhishPhage AI Report - ${escapeHtml(report.subject)}</title><style>
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
    <header><div><div class="brand">PhishPhage AI</div><h1>Email Analysis Report</h1></div><div><p><strong>Report generated</strong></p><p>${escapeHtml(formatReportDate(report.report_generated_at))}</p></div></header>
    <section class="verdict"><div class="metric"><span class="muted">Final classification</span><strong>${escapeHtml(report.final_classification)}</strong></div><div class="metric"><span class="muted">Risk score</span><strong>${escapeHtml(report.risk_score)}/100</strong></div><div class="metric"><span class="muted">Confidence</span><strong>${escapeHtml(Math.round(report.confidence * 100))}%</strong></div></section>
    <section class="section"><h2>Email and scan metadata</h2><dl class="metadata"><dt>Scan timestamp</dt><dd>${escapeHtml(formatReportDate(report.scan_timestamp))}</dd><dt>Subject</dt><dd>${escapeHtml(report.subject)}</dd><dt>Sender</dt><dd>${escapeHtml(report.sender)}</dd><dt>Recipients</dt><dd>${escapeHtml(report.recipients.join(', ') || 'Not recorded')}</dd><dt>Input mode</dt><dd>${escapeHtml(formatReportInputMode(report.input_mode))}</dd></dl></section>
    <section class="section allow-break"><h2>Detected indicators</h2>${indicators}</section>
    <section class="section"><h2>Extracted URLs</h2>${printableList(report.extracted_urls, 'No URLs recorded.')}</section>
    <section class="section allow-break"><h2>Attachment metadata</h2>${attachments}</section>
    <section class="section"><h2>Recommendations</h2>${printableList(report.recommendations, 'No recommendations recorded.')}</section>
    <section class="section"><h2>Engine metadata</h2><dl class="metadata"><dt>Rule engine</dt><dd>${escapeHtml(report.rule_engine.status)} · ${escapeHtml(report.rule_engine.version || 'Version not recorded')}</dd><dt>ML engine</dt><dd>${escapeHtml(report.ml_engine.status)} · ${escapeHtml(report.ml_engine.version || 'Version not recorded')}</dd><dt>Report schema</dt><dd>${escapeHtml(report.report_schema_version)}</dd><dt>Scan ID</dt><dd>${escapeHtml(report.scan_id)}</dd></dl></section>
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
