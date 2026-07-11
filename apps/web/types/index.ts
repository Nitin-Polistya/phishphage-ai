export interface ScanResult {
  id: string;
  timestamp: string;
  status: 'safe' | 'suspicious' | 'phishing';
  confidence: number;
  threatType?: string;
}

export interface DashboardStats {
  totalScans: number;
  phishingDetected: number;
  suspiciousEmails: number;
  safeEmails: number;
}