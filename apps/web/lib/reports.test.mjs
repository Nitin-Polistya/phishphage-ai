import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createPrintableReportHtml, createScanReport, serializeReportsToJson } from './reports.ts';

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

test('reports use the current PhishPhage AI brand in data and printable output', () => {
  const scan = scanWithFreshness('current', null);
  const report = createScanReport(scan, '2026-07-17T00:00:00.000Z');
  assert.equal(report.product, 'PhishPhage AI');
  assert.match(serializeReportsToJson([scan]), /"product": "PhishPhage AI"/);
  assert.match(createPrintableReportHtml(scan), /PhishPhage AI Report/);
});

test('current user-facing source files do not retain the previous display name', async () => {
  const previousDisplayName = new RegExp(['Phish', 'Shield'].join(''), 'i');
  const files = [
    '../app/layout.tsx',
    '../app/page.tsx',
    '../app/icon.svg',
    '../components/layout/sidebar.tsx',
    '../components/dashboard/dashboard-overview.tsx',
    '../components/reports/report-preview.tsx',
    './reports.ts',
    '../types/reports.ts',
  ];
  for (const file of files) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    assert.doesNotMatch(source, previousDisplayName, file);
  }
});
