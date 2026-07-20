import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  beginRequest,
  buildQuickPasteRawEmail,
  clearRequestTiming,
  completeRequestTiming,
  displayPrediction,
  displayRisk,
  isCurrentRequest,
  isValidEmailAddress,
  topReasons,
  validateQuickPaste,
} from './production-analysis-ui.ts';

const validQuickPaste = {
  senderName: '', senderEmail: '', recipientName: '', recipientEmail: '', replyTo: '', subject: 'Test', body: 'Hello',
};

test('accepts tolerant real-world email addresses after trimming', () => {
  for (const value of [
    'user@gmail.com',
    'SarahPolistya3401@gmail.com',
    'nitin.cs.23@sietpanchkula.ac.in',
    'user+tag@example.org',
    'first.last@sub.example.com',
    '  user@gmail.com  ',
  ]) assert.equal(isValidEmailAddress(value), true, value);
});

test('rejects malformed email addresses and identifies the exact field', () => {
  for (const value of ['user@gmail', 'user @gmail.com', '@example.com', 'user@', 'plain text']) {
    assert.equal(isValidEmailAddress(value), false, value);
    assert.deepEqual(validateQuickPaste({ ...validQuickPaste, senderEmail: value }), {
      field: 'senderEmail', message: 'Sender email must be a valid email address.',
    });
  }
});

test('optional email fields are validated only when non-empty', () => {
  assert.equal(validateQuickPaste(validQuickPaste), null);
  assert.equal(validateQuickPaste({ ...validQuickPaste, senderEmail: '  ', recipientEmail: '', replyTo: '' }), null);
  assert.deepEqual(validateQuickPaste({ ...validQuickPaste, replyTo: 'plain text' }), {
    field: 'replyTo', message: 'Reply-To must be a valid email address.',
  });
});

test('Quick Paste source trims fields and includes metadata but never attachment content', () => {
  const source = buildQuickPasteRawEmail(
    { ...validQuickPaste, senderName: ' Sarah ', senderEmail: ' USER@EXAMPLE.COM ' },
    [{ filename: 'invoice.pdf', content_type: 'application/pdf', size_bytes: 2048, disposition: 'attachment' }],
  );
  assert.match(source, /From: Sarah <USER@EXAMPLE.COM>/);
  assert.match(source, /Attachment metadata: invoice\.pdf \(application\/pdf\), 2048 bytes/);
  assert.equal(source.includes('attachment file contents'), false);
});

test('request timing resets and model processing never accumulates', () => {
  let timing = beginRequest(0);
  timing = completeRequestTiming(timing, 1, 16, 81);
  assert.equal(timing.modelProcessingMs, 16);
  timing = beginRequest(timing.sequence);
  assert.equal(timing.modelProcessingMs, null);
  assert.equal(timing.clientRoundTripMs, null);
  timing = completeRequestTiming(timing, 2, 38, 94);
  assert.equal(timing.modelProcessingMs, 38);
  assert.equal(timing.clientRoundTripMs, 94);
});

test('failed and cancelled requests clear timing', () => {
  const completed = completeRequestTiming(beginRequest(0), 1, 16, 80);
  assert.deepEqual(clearRequestTiming(completed, 1), { sequence: 1, modelProcessingMs: null, clientRoundTripMs: null });
});

test('stale responses cannot replace the active request state', () => {
  const second = beginRequest(1);
  const unchanged = completeRequestTiming(second, 1, 16, 80);
  assert.deepEqual(unchanged, second);
  assert.equal(isCurrentRequest(2, 1), false);
  assert.equal(isCurrentRequest(2, 2), true);
});

test('result helpers derive concern, verdict, and top reasons from response data', () => {
  assert.equal(displayRisk(61), 'High');
  assert.equal(displayPrediction({ prediction: 'legitimate', probability: 0.4 }), 'Suspicious');
  assert.deepEqual(topReasons({
    detected_indicators: ['display_name_mismatch'], phishing_signals: ['credential_request'],
    authentication_signals: [], url_indicators: ['shortened_url'], urgency_indicators: ['urgent_language'],
  }), ['display_name_mismatch', 'credential_request', 'urgent_language']);
});

test('component contract includes accessible selected mode, roving keyboard focus, and mode-specific labels', async () => {
  const source = await readFile(new URL('../components/analysis/production-analysis.tsx', import.meta.url), 'utf8');
  assert.match(source, /aria-selected=\{active\}/);
  assert.match(source, /tabIndex=\{active \? 0 : -1\}/);
  assert.match(source, /Current input mode:/);
  assert.match(source, /ArrowRight/);
  assert.match(source, /ArrowLeft/);
  assert.match(source, /event\.key === 'Home'/);
  assert.match(source, /event\.key === 'End'/);
  assert.match(source, /Analyze Quick Paste/);
  assert.match(source, /Analyze Raw Source/);
  assert.match(source, /Analyze Uploaded \.eml/);
});

test('component clears stale results before validation and exposes rich API-backed result sections', async () => {
  const formSource = await readFile(new URL('../components/analysis/production-analysis.tsx', import.meta.url), 'utf8');
  const resultSource = await readFile(new URL('../components/analysis/production-analysis-results.tsx', import.meta.url), 'utf8');
  assert.ok(formSource.indexOf('setResult(null);') < formSource.indexOf("if (mode === 'quick_paste')"));
  for (const heading of ['Final verdict', 'Recommended action', 'Top reasons', 'Relevant signal families', 'Detailed indicators', 'Analysis timeline', 'Recommendations', 'Technical metadata']) {
    assert.match(resultSource, new RegExp(heading));
  }
  assert.match(resultSource, /result\.recommendations\[0\]/);
  assert.match(resultSource, /topReasons\(result\.signals\)/);
});
