import { DashboardStats, ScanResult } from '../types';

export const MOCK_DASHBOARD_STATS: DashboardStats = {
  totalScans: 1284,
  phishingDetected: 142,
  suspiciousEmails: 89,
  safeEmails: 1053,
};

export const MOCK_RECENT_SCANS: ScanResult[] = [
  {
    id: 'scan_1',
    timestamp: '2026-07-11T10:30:00Z',
    status: 'phishing',
    confidence: 0.98,
    threatType: 'Credential Harvesting',
  },
  {
    id: 'scan_2',
    timestamp: '2026-07-11T09:15:00Z',
    status: 'safe',
    confidence: 0.99,
  },
  {
    id: 'scan_3',
    timestamp: '2026-07-11T08:45:00Z',
    status: 'suspicious',
    confidence: 0.65,
    threatType: 'Urgency/Threat Language',
  },
  {
    id: 'scan_4',
    timestamp: '2026-07-10T16:20:00Z',
    status: 'phishing',
    confidence: 0.92,
    threatType: 'Brand Impersonation',
  },
  {
    id: 'scan_5',
    timestamp: '2026-07-10T14:10:00Z',
    status: 'safe',
    confidence: 0.97,
  },
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