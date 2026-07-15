import { DashboardStats, ScanResult, ThreatVector } from '../types';

export const MOCK_DASHBOARD_STATS: DashboardStats = {
  totalScans: 1284,
  phishingDetected: 142,
  suspiciousEmails: 89,
  safeEmails: 1053,
  averageRiskScore: 28,
};

export const MOCK_RECENT_SCANS: ScanResult[] = [
  {
    id: 'scan_1',
    subject: 'Password expires today',
    sender: 'security@microsoft-verify-account.com',
    timestamp: '2026-07-11T10:30:00Z',
    status: 'phishing',
    riskScore: 96,
    confidence: 0.98,
    threatType: 'Credential Harvesting',
  },
  {
    id: 'scan_2',
    subject: 'Quarterly benefits update',
    sender: 'people@northstar.example',
    timestamp: '2026-07-11T09:15:00Z',
    status: 'safe',
    riskScore: 4,
    confidence: 0.99,
  },
  {
    id: 'scan_3',
    subject: 'Immediate action required',
    sender: 'billing@account-review.example',
    timestamp: '2026-07-11T08:45:00Z',
    status: 'suspicious',
    riskScore: 64,
    confidence: 0.65,
    threatType: 'Urgency/Threat Language',
  },
  {
    id: 'scan_4',
    subject: 'New document shared with you',
    sender: 'notifications@sharepoint-access.example',
    timestamp: '2026-07-10T16:20:00Z',
    status: 'phishing',
    riskScore: 91,
    confidence: 0.92,
    threatType: 'Brand Impersonation',
  },
  {
    id: 'scan_5',
    subject: 'Engineering stand-up notes',
    sender: 'maya@northstar.example',
    timestamp: '2026-07-10T14:10:00Z',
    status: 'safe',
    riskScore: 7,
    confidence: 0.97,
  },
];

export const MOCK_THREAT_VECTORS: ThreatVector[] = [
  { label: 'Credential harvesting', count: 42, severity: 'high' },
  { label: 'Brand impersonation', count: 31, severity: 'high' },
  { label: 'Urgency language', count: 24, severity: 'medium' },
  { label: 'Suspicious links', count: 18, severity: 'medium' },
  { label: 'Malware delivery', count: 9, severity: 'low' },
];

export const MOCK_EXAMPLE_EMAIL = `From: Security Alert <security@microsoft-verify-account.com>
To: user@example.com
Subject: Unusual Sign-in Activity Detected

Dear User,

We detected an unusual sign-in attempt to your Microsoft account from a new location (Ip: 192.168.1.1 - Moscow, RU).

If this was not you, please verify your identity immediately to prevent account suspension.

Click here to verify your account: http://secure-microsoft-login.net/verify-identity

Thank you,
Microsoft Security Team`;
