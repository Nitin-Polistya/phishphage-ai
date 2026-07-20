import test from 'node:test';
import assert from 'node:assert/strict';

import { buildQuickPasteRawEmail, displayPrediction, displayRisk, uniqueSignalValues, validateRawEmail } from './inference-ui.mjs';

test('rejects empty and oversized raw email input', () => {
  assert.equal(validateRawEmail('   '), 'Paste an email before starting analysis.');
  assert.equal(validateRawEmail('a'.repeat(2_000_001)), 'This email exceeds the 2 MB processing limit.');
  assert.equal(validateRawEmail('From: sender@example.com\n\nHello'), null);
});

test('maps risk scores to accessible labels', () => {
  assert.deepEqual([displayRisk(0), displayRisk(30), displayRisk(60), displayRisk(85)], ['Low', 'Moderate', 'High', 'Critical']);
});

test('maps backend prediction without claiming certainty', () => {
  assert.equal(displayPrediction({ prediction: 'phishing', probability: 0.2 }), 'Phishing');
  assert.equal(displayPrediction({ prediction: 'legitimate', probability: 0.5 }), 'Suspicious');
  assert.equal(displayPrediction({ prediction: 'legitimate', probability: 0.1 }), 'Low risk');
});

test('deduplicates repeated signal labels before rendering', () => {
  assert.deepEqual(uniqueSignalValues(['actionable_url', 'actionable_url', 'auth']), ['actionable_url', 'auth']);
});

test('builds deterministic Quick Paste source without fake authentication headers', () => {
  const source = buildQuickPasteRawEmail({ senderName: 'Ops', senderEmail: 'ops@example.org', recipientName: '', recipientEmail: '', replyTo: '', subject: 'Notes', body: 'Hello' }, [{ filename: 'notes.pdf', mimeType: 'application/pdf', sizeBytes: '1024' }]);
  assert.equal(source, 'From: Ops <ops@example.org>\nSubject: Notes\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\nHello\nAttachment metadata: notes.pdf (application/pdf), 1024 bytes');
  assert.equal(source.includes('Authentication-Results'), false);
});
