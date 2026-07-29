import type { AnalysisCompletenessState, AnalysisInputMode, EmailAttachmentMetadata, ThreatClassification, ThreatSeverity } from './analysis';

export interface ScanIndicator {
  code: string;
  title: string;
  category: string;
  severity: ThreatSeverity;
  score: number;
  description?: string;
  evidence?: string | null;
  sourceEngine?: string;
  evidenceType?: string;
  tone?: string;
  contributesToScore?: boolean;
  provenance?: string | null;
}

export interface ScanDetails {
  replyTo: string | null;
  recipients: string[];
  cc: string[];
  messageDate: string | null;
  messageId: string | null;
  recommendations: string[];
  urls: string[];
  urlEvidence?: Array<{
    url: string;
    sourceType: string;
    userActionable: boolean;
    externalDomain?: boolean | null;
    securityRelevance?: string;
  }>;
  mailtoEvidence?: Array<{
    destinationDomains: string[];
    recipientCount: number;
    visibleText: string;
    actionType: string;
    userActionable: boolean;
    malformed: boolean;
  }>;
  attachments: EmailAttachmentMetadata[];
  inputMode?: AnalysisInputMode;
  ruleEngine?: {
    status: 'active';
    version: string;
  };
  mlEngine?: {
    status: 'available' | 'unavailable';
    version: string | null;
  };
  ruleRawScore?: number | null;
  ruleAdjustedScore?: number | null;
  mlPrediction?: string | null;
  mlPhishingProbability?: number | null;
  mlThreshold?: number | null;
  finalDecisionConfidence?: number | null;
  ruleMlAgreement?: string | null;
  fusionReason?: string | null;
  analysisCompleteness?: AnalysisCompletenessState;
  analysisCompletenessStatus?: 'complete' | 'partial' | 'incomplete' | 'stale' | 'unavailable' | string;
  missingEvidence?: string[];
  incompleteReasonCodes?: string[];
  decisionSafetyStatus?: 'eligible' | 'needs_review' | 'unable_to_verify' | 'rescan_required' | string;
  presentationState?: string;
  requiresRescan?: boolean;
  safeVerdictAllowed?: boolean;
  enginesRequested?: string[];
  enginesCompleted?: string[];
  enginesFailed?: string[];
  decisionSource?: string;
  fusionPerformed?: boolean;
  fallbackUsed?: boolean;
  fallbackReason?: string | null;
  fusionPolicyVersion?: string;
  fusionInputs?: Record<string, unknown>;
  fusionComponents?: string[];
  ruleWeight?: number;
  mlWeight?: number;
  safetyFloorApplied?: boolean;
  safetyFloorRuleId?: string | null;
  appliedFloorReason?: string | null;
  disagreementResolution?: string | null;
  preFloorScore?: number | null;
  postFloorScore?: number | null;
  dominantEvidenceSource?: string;
  evidenceFamilies?: string[];
  highConfidenceRuleEvidence?: boolean;
  protectiveEvidence?: string[];
  positiveAuthenticationEvidence?: Array<{
    mechanism: string;
    state: string;
    domain: string | null;
    alignedWithFrom: boolean | null;
    result?: string | null;
    displayLabel?: string;
    detail?: string | null;
  }>;
  authenticationEvidence?: Array<{
    mechanism: string;
    state: string;
    domain?: string | null;
    alignedWithFrom?: boolean | null;
    result?: string | null;
    displayLabel?: string;
    detail?: string | null;
  }>;
  authenticationEvidenceStatus?: 'available' | 'passed' | 'unavailable' | 'failed' | 'inconclusive' | 'conflicting' | string;
  analysisFreshness?: 'current' | 'stale';
  staleReason?: string | null;
  linkLanguagePresent?: boolean;
  actualUrlCount?: number;
  htmlAnchorCount?: number;
  urlExtractionStatus?: string;
  urlExtractionReason?: string | null;
  actionableUrlCount?: number;
  trackingPixelCount?: number;
  externalTrackingPixelCount?: number;
  mailtoCount?: number;
  actionableMailtoCount?: number;
  mailtoDestinationsRedactedOrNormalized?: string[];
  mailtoDomainCount?: number;
  mailtoExternalDomainMismatch?: boolean;
  mailtoPersonalProvider?: boolean;
  mailtoActionTypes?: string[];
  mailtoActionType?: string;
  currentRuleVersion?: string | null;
  storedRuleVersion?: string | null;
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
