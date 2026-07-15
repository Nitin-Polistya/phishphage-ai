import type { AnalysisInputMode, EmailAttachmentMetadata, ThreatClassification, ThreatSeverity } from './analysis';

export interface ReportIndicator {
  code: string;
  title: string;
  category: string;
  severity: ThreatSeverity;
  score: number;
  description: string | null;
  evidence: string | null;
}

export interface ScanReportData {
  report_schema_version: '1.0';
  product: 'PhishPhage AI';
  report_generated_at: string;
  scan_id: string;
  scan_timestamp: string;
  subject: string;
  sender: string;
  recipients: string[];
  input_mode: AnalysisInputMode | 'not_recorded';
  final_classification: ThreatClassification;
  risk_score: number;
  confidence: number;
  rule_engine: { status: 'active' | 'unknown'; version: string | null };
  ml_engine: { status: 'available' | 'unavailable' | 'unknown'; version: string | null };
  detected_indicators: ReportIndicator[];
  recommendations: string[];
  extracted_urls: string[];
  attachments: EmailAttachmentMetadata[];
  privacy_disclaimer: string;
}
