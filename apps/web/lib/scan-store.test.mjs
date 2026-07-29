import assert from 'node:assert/strict';
import test from 'node:test';

import { createProductionScanRecord, readScans, saveScan } from './scan-store.ts';
import { createPrintableReportHtml, createScanReport } from './reports.ts';

function installStorage() {
  const values = new Map();
  globalThis.window = {
    localStorage: {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => true,
  };
}

function response(overrides = {}) {
  return {
    model_id: 'phase-c-logistic-regression-v1', model_version: '1.0.0', prediction: 'legitimate',
    probability: 0.1, risk_score: 10, confidence: 0.9, threshold_used: 0.5,
    feature_families: ['lexical'], signals: {
      detected_indicators: [], phishing_signals: [], authentication_signals: [], url_indicators: [], urgency_indicators: [],
    }, recommendations: ['Verify independently.'], processing_time_ms: 2,
    final_classification: 'safe', final_risk_score: 5, final_decision_confidence: 0.8,
    analysis_completeness_status: 'complete', analysis_freshness: 'current', decision_safety_status: 'eligible',
    presentation_state: 'safe', safe_verdict_allowed: true, requires_rescan: false,
    engines_requested: ['rules', 'ml'], engines_completed: ['rules', 'ml', 'fusion'], engines_failed: [],
    fusion_performed: true, decision_source: 'rule_ml_fusion', rule_findings: [],
    fusion_policy_version: 'asymmetric-safety-v1',
    current_rule_version: 'rules-v3.1.0', stored_rule_version: 'rules-v3.1.0',
    authentication_evidence_status: 'available', extracted_urls: [], actual_url_count: 0,
    url_evidence: [], url_extraction_status: 'not_present',
    ...overrides,
  };
}

test('fresh complete safe scans retain safe eligibility', () => {
  installStorage();
  const scan = createProductionScanRecord(response(), 'From: Alice <alice@example.com>\nSubject: Update\n\nHello', 'raw_email');
  assert.equal(scan.details.safeVerdictAllowed, true);
  saveScan(scan);
  assert.equal(readScans()[0].details.safeVerdictAllowed, true);
  assert.equal(readScans()[0].details.analysisFreshness, 'current');
});

test('stale safe scans migrate to re-scan required and export conservatively', () => {
  installStorage();
  const reason = 'Expected rule engine rules-v3.1.0; received rules-v2.0.0.';
  const scan = createProductionScanRecord(response({
    analysis_freshness: 'stale', stale_reason: reason, safe_verdict_allowed: false,
    presentation_state: 'rescan_required', decision_safety_status: 'rescan_required',
    stored_rule_version: 'rules-v2.0.0',
  }), 'From: Alice <alice@example.com>\nSubject: Update\n\nHello', 'raw_email');
  saveScan(scan);
  const stored = readScans()[0];
  assert.equal(stored.details.analysisFreshness, 'stale');
  assert.equal(stored.details.staleReason, reason);
  assert.equal(stored.details.safeVerdictAllowed, false);
  const report = createScanReport(stored);
  assert.equal(report.analysis_freshness, 'stale');
  assert.equal(report.stale_reason, reason);
  assert.equal(report.safe_verdict_allowed, false);
  assert.equal(report.final_classification, 'safe');
});

test('legacy safe scans preserve the original classification and mark fusion policy unknown', () => {
  installStorage();
  const legacy = JSON.parse(JSON.stringify(createProductionScanRecord(response(), 'From: Alice <alice@example.com>\nSubject: Update\n\nHello', 'raw_email')));
  delete legacy.details.fusionPolicyVersion;
  window.localStorage.setItem('phishphage.scan-records.v1', JSON.stringify([legacy]));
  const stored = readScans()[0];
  assert.equal(stored.classification, 'safe');
  assert.equal(stored.details.fusionPolicyVersion, 'unknown');
  assert.equal(stored.details.safeVerdictAllowed, false);
  assert.equal(stored.details.presentationState, 'needs_review');
});

test('reports preserve pre-floor, post-floor, and mailto/tracking metadata', () => {
  installStorage();
  const scan = createProductionScanRecord(response({
    final_classification: 'phishing', final_risk_score: 82, risk_score: 23,
    safety_floor_applied: true, safety_floor_rule_id: 'brand_impersonation_with_routing_mismatch',
    pre_floor_score: 56, post_floor_score: 82, evidence_families: ['identity', 'routing', 'authentication'],
    mailto_count: 3, actionable_mailto_count: 3, mailto_destinations_redacted_or_normalized: ['gmail.com'],
    tracking_pixel_count: 1, external_tracking_pixel_count: 1,
  }), 'From: Microsoft <alerts@example.com>\nSubject: Alert\n\nHello', 'raw_email');
  const report = createScanReport(scan);
  assert.equal(report.ml_phishing_probability, 0.1);
  assert.equal(report.pre_floor_score, 56);
  assert.equal(report.post_floor_score, 82);
  assert.equal(report.safety_floor_rule_id, 'brand_impersonation_with_routing_mismatch');
  assert.deepEqual(report.evidence_families, ['identity', 'routing', 'authentication']);
  assert.equal(report.mailto_count, 3);
  assert.equal(report.external_tracking_pixel_count, 1);
  const printable = createPrintableReportHtml(scan, '2026-07-29T00:00:00.000Z');
  assert.match(printable, /Pre-floor \/ post-floor/);
  assert.match(printable, /brand_impersonation_with_routing_mismatch/);
  assert.match(printable, /External tracking pixels/);
});
