export type ReviewLabel = 'safe' | 'suspicious' | 'phishing' | 'unable_to_determine';
export type ReviewMode = 'independent' | 'ai_assisted';
export type SourceClaimedLabel = 'safe' | 'phishing' | 'suspicious' | 'unknown';
export type GoldReviewState = 'pending' | 'reviewed' | 'needs_second_review' | 'approved' | 'rejected' | 'archived';

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

export interface GoldDatasetExportFile {
  filename: string;
  status: 'written';
  size_bytes: number;
}

export interface GoldDatasetExportResponse {
  exported_count: number;
  exported_at: string;
  output_location: string;
  files: GoldDatasetExportFile[];
  all_files_written: boolean;
  privacy_contract: string;
}

export interface DatasetReviewQueueItem {
  item_id: string;
  batch_id: string;
  row_number: number;
  source_sample_id: string;
  source_dataset: string;
  campaign_id: string;
  language: string;
  source_claimed_label: SourceClaimedLabel;
  current_human_label: ReviewLabel | null;
  state: GoldReviewState;
  confidence: number | null;
  duplicate_status: string;
  duplicate_reasons: string[];
  second_review_required: boolean;
  second_review_complete: boolean;
  review_id: string | null;
  subject_preview: string;
  body_excerpt: string;
  sender_domain: string;
  reply_to_domain: string;
  authentication_summary: string[];
  url_domains: string[];
  url_structural_flags: string[];
  attachment_metadata: string;
}

export interface BatchReviewResponse {
  batch_id: string;
  source_format: 'csv' | 'jsonl';
  imported_count: number;
  duplicate_count: number;
  imported_at: string;
  items: DatasetReviewQueueItem[];
  warnings: string[];
}

export interface DatasetReviewQueueResponse {
  items: DatasetReviewQueueItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface BulkFailure {
  item_id: string;
  reason: string;
}

export interface BulkOperationResponse {
  bulk_operation_id: string;
  operation: string;
  requested_count: number;
  affected_count: number;
  approved_count: number;
  skipped_count: number;
  atomic: boolean;
  failures: BulkFailure[];
  items: DatasetReviewQueueItem[];
}
