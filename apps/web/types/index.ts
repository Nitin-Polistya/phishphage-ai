import type { ThreatClassification, ThreatSeverity } from './analysis';

export interface ScanIndicator {
  code: string;
  title: string;
  category: string;
  severity: ThreatSeverity;
  score: number;
}

export interface ScanRecord {
  id: string;
  subject: string;
  sender: string;
  timestamp: string;
  classification: ThreatClassification;
  riskScore: number;
  confidence: number;
  indicators: ScanIndicator[];
  attachmentCount: number;
  extractedUrlCount: number;
}

export interface DashboardStats {
  totalScans: number;
  phishingDetected: number;
  suspiciousEmails: number;
  safeEmails: number;
  averageRiskScore: number;
}

export interface ThreatVector {
  label: string;
  count: number;
  severity: 'low' | 'medium' | 'high';
}
