import type { DashboardStats, ScanIndicator, ScanRecord, ThreatVector } from '@/types';
import type { ThreatSeverity, UnifiedAnalysisResponse } from '@/types/analysis';

const SCAN_STORAGE_KEY = 'phishphage.scan-records.v1';
const SCAN_STORAGE_EVENT = 'phishphage:scan-records-changed';

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
    && details.attachments.every(isAttachment);
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

export function createScanRecord(result: UnifiedAnalysisResponse): ScanRecord {
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
      attachments: result.parser.attachments.map((attachment) => ({ ...attachment })),
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
      .sort((left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime());
  } catch {
    return [];
  }
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
