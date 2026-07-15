export type ThreatClassification = 'safe' | 'suspicious' | 'phishing';
export type ThreatSeverity = 'low' | 'medium' | 'high';
export type AnalysisInputMode = 'quick_paste' | 'raw_email' | 'eml_upload';

export interface EmailAddress {
  name: string | null;
  address: string;
}

export interface EmailAttachmentMetadata {
  filename: string | null;
  content_type: string | null;
  size_bytes: number;
  disposition: string | null;
  extension?: string | null;
  suspicious_extension?: boolean;
}

export interface ParsedEmail {
  subject: string | null;
  sender: EmailAddress | null;
  reply_to: EmailAddress | null;
  recipients: EmailAddress[];
  cc: EmailAddress[];
  date: string | null;
  message_id: string | null;
  body_text: string;
  body_html: string | null;
  headers: Record<string, string>;
  extracted_urls: string[];
  attachments: EmailAttachmentMetadata[];
}

export interface ThreatSignal {
  code: string;
  category: string;
  severity: ThreatSeverity;
  title: string;
  description: string;
  score: number;
  evidence: string | null;
}

export interface RuleAnalysis {
  classification: ThreatClassification;
  risk_score: number;
  confidence: number;
  signals: ThreatSignal[];
  recommendations: string[];
  engine_version: string;
}

export interface MLAnalysis {
  status: 'available' | 'unavailable';
  prediction: 'phishing' | 'legitimate' | null;
  phishing_probability: number | null;
  legitimate_probability: number | null;
  model_version: string | null;
  reason: string | null;
}

export interface FinalDecision {
  classification: ThreatClassification;
  risk_score: number;
  confidence: number;
}

export interface UnifiedAnalysisResponse {
  parser: ParsedEmail;
  rule_analysis: RuleAnalysis;
  ml_analysis: MLAnalysis;
  decision: FinalDecision;
  recommendations: string[];
}

export interface AnalysisRequest {
  input_mode: AnalysisInputMode;
  raw_email?: string;
  sender_name?: string;
  sender_email?: string;
  recipient_name?: string;
  recipient_email?: string;
  reply_to?: string;
  subject?: string;
  body?: string;
  attachments?: EmailAttachmentMetadata[];
}
