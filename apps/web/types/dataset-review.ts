export type ReviewLabel = 'safe' | 'suspicious' | 'phishing' | 'unable_to_determine';
export type ReviewMode = 'independent' | 'ai_assisted';

export interface DatasetReviewStatus {
  enabled: boolean;
  local_only: boolean;
  gemini_enabled: boolean;
  configured: boolean;
  provider_ready: boolean;
  model_name: string | null;
  prompt_version: string;
  session_limit: number;
  daily_limit: number;
  batch_enabled: boolean;
  storage: string;
  notice: string;
}

export interface SanitizedReviewPayload {
  sample_id: string;
  subject: string;
  display_name: string;
  sender_domain: string;
  reply_to_domain: string;
  return_path_domain: string;
  authentication_summary: string[];
  body_excerpt: string;
  visible_html_text: string;
  url_domains: string[];
  url_structural_flags: string[];
  attachment_extension: string;
  attachment_mime: string;
  parser_evidence: string[];
  candidate_campaign_category: string;
  model_name: string;
  prompt_version: string;
  sanitized_payload_hash: string;
}

export interface DatasetReviewPreview {
  enabled: boolean;
  payload: SanitizedReviewPayload;
  payload_bytes: number;
  payload_hash: string;
  sent_fields: string[];
  notice: string;
}

export interface GeminiEvidenceItem {
  category: string;
  title: string;
  explanation: string;
  evidence_strength: string;
  supports: string;
}

export interface GeminiSuggestion {
  suggestion_id: string;
  sample_id: string;
  suggested_label: ReviewLabel;
  confidence: number;
  summary: string;
  evidence: GeminiEvidenceItem[];
  contrary_evidence: GeminiEvidenceItem[];
  claimed_organization: string | null;
  sender_domain_assessment: string;
  authentication_assessment: string;
  action_requested: string | null;
  likely_campaign: string | null;
  missing_evidence: string[];
  ambiguity_notes: string[];
  reviewer_questions: string[];
  safety_notes: string[];
  model_name: string;
  prompt_version: string;
  sanitized_payload_hash: string;
  generated_at: string;
  provider_usage: { input_tokens: number | null; output_tokens: number | null; total_tokens: number | null };
}

export interface GoldDatasetDashboard {
  total_samples: number;
  review_completion: number;
  approved_samples: number;
  review_queue: Record<string, number>;
  reviewer_agreement: {
    reviewer_a: string;
    reviewer_b: string;
    sample_count: number;
    agreement_count: number;
    disagreement_count: number;
    agreement_rate: number;
    cohen_kappa: number;
  } | null;
  label_distribution: Record<string, number>;
  language_distribution: Record<string, number>;
  confidence_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  second_review_count: number;
}
