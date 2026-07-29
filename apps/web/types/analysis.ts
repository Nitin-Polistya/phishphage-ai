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
    source_type: 'anchor_href' | 'plain_text' | 'form_action' | 'image_src' | 'css_resource' | 'tracking_pixel' | 'document_metadata' | 'namespace_or_dtd' | 'mailto';
    user_actionable: boolean;
    external_domain?: boolean | null;
    security_relevance?: string;
  }>;
  mailto_evidence?: Array<{
    destination_domains: string[];
    recipient_count: number;
    visible_text: string;
    action_type: string;
    user_actionable: boolean;
    malformed: boolean;
  }>;
  html_links?: Array<{
    visible_text: string;
    href: string;
    visible_domain: string | null;
    href_domain: string | null;
    domain_mismatch: boolean;
  }>;
  link_language_present?: boolean;
  actual_url_count?: number;
  html_anchor_count?: number;
  url_extraction_status?: string;
  url_extraction_reason?: string | null;
  actionable_url_count?: number;
  tracking_pixel_count?: number;
  external_tracking_pixel_count?: number;
  mailto_count?: number;
  actionable_mailto_count?: number;
  mailto_destinations_redacted_or_normalized?: string[];
  mailto_domain_count?: number;
  mailto_external_domain_mismatch?: boolean;
  mailto_personal_provider?: boolean;
  mailto_action_types?: string[];
  mailto_action_type?: string;
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
  recommendation?: string;
  source_engine?: string;
  evidence_type?: string;
  user_impact?: string | null;
  tone?: string;
  confidence?: number | null;
  mapped_title?: string | null;
  mapped_description?: string | null;
  contributes_to_score?: boolean;
  provenance?: string | null;
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
export type AnalysisCompletenessLevel = 'complete' | 'partial' | 'incomplete' | 'stale' | 'unavailable';

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
  analysis_state?: AnalysisCompletenessLevel;
  missing_evidence?: string[];
  incomplete_reason_codes?: string[];
  parser_success?: boolean;
  rules_available?: boolean;
  ml_available?: boolean;
  fusion_available?: boolean;
}

export interface FinalDecision {
  classification: ThreatClassification;
  risk_score: number;
  confidence: number;
  fusion_reason?: string | null;
  limited_authentication_evidence?: boolean;
  fusion_policy_version?: string;
  fusion_inputs?: Record<string, unknown>;
  fusion_components?: string[];
  rule_weight?: number;
  ml_weight?: number;
  applied_floor?: boolean;
  applied_floor_reason?: string | null;
  dominant_evidence_source?: string;
  disagreement_resolution?: string | null;
  safety_floor_applied?: boolean;
  safety_floor_rule_id?: string | null;
  pre_floor_score?: number | null;
  post_floor_score?: number | null;
  evidence_families?: string[];
  high_confidence_rule_evidence?: boolean;
  protective_evidence?: string[];
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
    state: 'pass' | 'fail' | 'inconclusive' | 'missing' | 'unavailable' | 'malformed' | 'conflicting' | string;
    domain: string | null;
    aligned_with_from: boolean | null;
    result?: string | null;
    display_label?: string;
    detail?: string | null;
  }>;
  authentication_evidence_status?: 'available' | 'unavailable' | 'failed' | 'inconclusive';
  analysis_freshness?: 'current' | 'stale';
  stale_reason?: string | null;
  analysis_completeness_status?: AnalysisCompletenessLevel;
  missing_evidence?: string[];
  incomplete_reason_codes?: string[];
  decision_safety_status?: 'eligible' | 'needs_review' | 'unable_to_verify' | 'rescan_required';
  presentation_state?: 'safe' | 'suspicious' | 'phishing' | 'needs_review' | 'unable_to_verify' | 'rescan_required';
  requires_rescan?: boolean;
  safe_verdict_allowed?: boolean;
  engines_requested?: string[];
  engines_completed?: string[];
  engines_failed?: string[];
  decision_source?: string;
  fusion_performed?: boolean;
  fallback_used?: boolean;
  fallback_reason?: string | null;
  authentication_evidence?: Array<{
    mechanism: string;
    state: string;
    domain: string | null;
    aligned_with_from: boolean | null;
    result?: string | null;
    display_label?: string;
    detail?: string | null;
  }>;
  link_language_present?: boolean;
  actual_url_count?: number;
  html_anchor_count?: number;
  url_extraction_status?: string;
  url_extraction_reason?: string | null;
  current_rule_version?: string | null;
  stored_rule_version?: string | null;
  fusion_policy_version?: string;
  fusion_inputs?: Record<string, unknown>;
  fusion_components?: string[];
  rule_weight?: number;
  ml_weight?: number;
  safety_floor_applied?: boolean;
  safety_floor_rule_id?: string | null;
  applied_floor_reason?: string | null;
  disagreement_resolution?: string | null;
  pre_floor_score?: number | null;
  post_floor_score?: number | null;
  dominant_evidence_source?: string;
  evidence_families?: string[];
  high_confidence_rule_evidence?: boolean;
  protective_evidence?: string[];
  actionable_url_count?: number;
  tracking_pixel_count?: number;
  external_tracking_pixel_count?: number;
  mailto_count?: number;
  actionable_mailto_count?: number;
  mailto_destinations_redacted_or_normalized?: string[];
  mailto_domain_count?: number;
  mailto_external_domain_mismatch?: boolean;
  mailto_personal_provider?: boolean;
  mailto_action_types?: string[];
  mailto_action_type?: string;
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
