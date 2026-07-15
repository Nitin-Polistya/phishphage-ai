export interface ScanResult {
  id: string;
  subject: string;
  sender: string;
  timestamp: string;
  status: 'safe' | 'suspicious' | 'phishing';
  riskScore: number;
  confidence: number;
  threatType?: string;
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
