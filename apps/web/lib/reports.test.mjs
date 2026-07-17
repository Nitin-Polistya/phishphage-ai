import assert from 'node:assert/strict';
import test from 'node:test';

import { createScanReport } from './reports.ts';

function scanWithFreshness(status, reason) {
  return {
    id: 'scan-1', timestamp: '2026-07-17T00:00:00.000Z', subject: 'Test', sender: 'sender@example.com',
    classification: 'safe', riskScore: 5, confidence: 0.6, indicators: [], attachmentCount: 0,
    extractedUrlCount: 0,
    details: {
      replyTo: null, recipients: [], cc: [], messageDate: null, messageId: null,
      recommendations: [], urls: [], attachments: [], analysisFreshness: status, staleReason: reason,
    },
  };
}

test('current report freshness never carries a stale reason', () => {
  const report = createScanReport(scanWithFreshness('current', 'contradictory legacy value'));
  assert.equal(report.analysis_freshness, 'current');
  assert.equal(report.stale_reason, null);
});

test('stale report freshness preserves the exact stale reason', () => {
  const reason = 'Expected rules-v3.1.0; received rules-v1.';
  const report = createScanReport(scanWithFreshness('stale', reason));
  assert.equal(report.analysis_freshness, 'stale');
  assert.equal(report.stale_reason, reason);
});
