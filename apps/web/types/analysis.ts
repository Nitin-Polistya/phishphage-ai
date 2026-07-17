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
  body_visible_text?: string;
  headers: Record<string, string>;
  extracted_urls: string[];
  url_evidence?: Array<{
    url: string;
    source_type: 'anchor_href' | 'plain_text' | 'form_action' | 'image_src' | 'css_resource' | 'tracking_pixel' | 'document_metadata' | 'namespace_or_dtd';
    user_actionable: boolean;
  }>;
  html_links?: Array<{
    visible_text: string;
    href: string;
    visible_domain: string | null;
    href_domain: string | null;
    domain_mismatch: boolean;
  }>;
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
  decision_threshold?: number | null;
}

export type AnalysisCompletenessState = 'body_text_only' | 'structured_fields' | 'html_content' | 'complete_raw_email';

export interface AnalysisCompleteness {
  state: AnalysisCompletenessState;
  limited_evidence: boolean;
  warning: string | null;
  has_from_header: boolean;
  has_reply_to: boolean;
  has_return_path: boolean;
  has_authentication_results: boolean;
  has_spf_result: boolean;
  has_dkim_result: boolean;
  has_dmarc_result: boolean;
  has_html_source: boolean;
  has_real_href_destinations: boolean;
  has_attachment_metadata: boolean;
  has_complete_raw_headers: boolean;
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
  analysis_completeness?: AnalysisCompleteness;
  engine_agreement?: 'agreement' | 'disagreement' | 'ml_unavailable';
  rule_raw_score?: number | null;
  rule_adjusted_score?: number | null;
  ml_prediction?: 'phishing' | 'legitimate' | null;
  ml_phishing_probability?: number | null;
  ml_threshold?: number | null;
  final_decision_confidence?: number | null;
  rule_ml_agreement?: 'agreement' | 'disagreement' | 'ml_unavailable' | null;
  fusion_reason?: string | null;
  positive_authentication_evidence?: Array<{
    mechanism: string;
    state: 'pass' | 'fail' | 'inconclusive' | 'missing';
    domain: string | null;
    aligned_with_from: boolean | null;
  }>;
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
