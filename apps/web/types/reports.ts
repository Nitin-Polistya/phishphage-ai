import type { AnalysisCompletenessState, AnalysisInputMode, EmailAttachmentMetadata, ThreatClassification, ThreatSeverity } from './analysis';

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
  report_schema_version: '1.1';
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
  final_decision_confidence: number | null;
  rule_raw_score: number | null;
  rule_adjusted_score: number | null;
  ml_prediction: string | null;
  ml_phishing_probability: number | null;
  ml_threshold: number | null;
  rule_ml_agreement: string | null;
  fusion_reason: string | null;
  analysis_completeness: AnalysisCompletenessState | 'not_recorded';
  positive_authentication_evidence: Array<{
    mechanism: string;
    state: string;
    domain: string | null;
    aligned_with_from: boolean | null;
  }>;
  authentication_evidence_status: 'available' | 'unavailable' | 'failed' | 'inconclusive';
  url_evidence: Array<{ url: string; source_type: string; user_actionable: boolean }>;
  analysis_freshness: 'current' | 'stale';
  stale_reason: string | null;
  rule_engine: { status: 'active' | 'unknown'; version: string | null };
  ml_engine: { status: 'available' | 'unavailable' | 'unknown'; version: string | null };
  detected_indicators: ReportIndicator[];
  recommendations: string[];
  extracted_urls: string[];
  attachments: EmailAttachmentMetadata[];
  privacy_disclaimer: string;
}
