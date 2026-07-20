export interface InferenceSignals {
  detected_indicators: string[];
  phishing_signals: string[];
  authentication_signals: string[];
  url_indicators: string[];
  urgency_indicators: string[];
}

export interface PredictionResponse {
  model_id: string;
  model_version: string;
  prediction: 'phishing' | 'legitimate' | string;
  probability: number;
  risk_score: number;
  confidence: number;
  threshold_used: number;
  feature_families: string[];
  signals: InferenceSignals;
  recommendations: string[];
  processing_time_ms: number;
}

export interface HealthResponse {
  status: string;
  service: string;
  firebase: string;
  loaded_model: string | null;
  model_version: string | null;
  calibration: string | null;
  deployment_candidate: boolean;
  activated: boolean;
  pipeline_sha: string | null;
  registry_status?: string | null;
}
