import type { EmailAttachmentMetadata, ThreatClassification, ThreatSeverity } from './analysis';

export interface ScanIndicator {
  code: string;
  title: string;
  category: string;
  severity: ThreatSeverity;
  score: number;
  description?: string;
  evidence?: string | null;
}

export interface ScanDetails {
  replyTo: string | null;
  recipients: string[];
  cc: string[];
  messageDate: string | null;
  messageId: string | null;
  recommendations: string[];
  urls: string[];
  attachments: EmailAttachmentMetadata[];
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
  details?: ScanDetails;
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
