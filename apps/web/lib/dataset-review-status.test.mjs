import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  DEFAULT_DATASET_REVIEW_API_BASE_URL,
  DATASET_REVIEW_STATUS_TIMEOUT_MS,
  DatasetReviewStatusError,
  parseDatasetReviewStatus,
  requestDatasetReviewStatus,
  resolveDatasetReviewApiBaseUrl,
  toDatasetReviewServiceState,
} from './dataset-review-status.ts';

const enabledStatus = {
  enabled: true,
  local_only: true,
  gemini_enabled: false,
  configured: true,
  provider_ready: false,
  model_name: '',
  prompt_version: 'gemini-review-v1',
  session_limit: 5,
  daily_limit: 20,
  batch_enabled: false,
  storage: 'local SQLite; sanitized metadata only',
  notice: 'Human approval is required.',
};

test('maps an enabled backend status response without changing its fields', () => {
  assert.deepEqual(parseDatasetReviewStatus(enabledStatus), enabledStatus);
});

test('maps a disabled backend status response as disabled rather than unavailable', () => {
  assert.equal(parseDatasetReviewStatus({ ...enabledStatus, enabled: false }).enabled, false);
});

test('keeps Dataset Review enabled when Gemini is not configured', () => {
  const state = toDatasetReviewServiceState({ ...enabledStatus, configured: false, provider_ready: false, model_name: '' });
  assert.equal(state.kind, 'enabled');
  assert.equal(state.status.configured, false);
  assert.equal(state.status.gemini_enabled, false);
});

test('maps a valid disabled response to a terminal disabled state', () => {
  assert.equal(toDatasetReviewServiceState({ ...enabledStatus, enabled: false }).kind, 'disabled');
});

test('uses the safe local API default and trims configured origins', () => {
  assert.equal(resolveDatasetReviewApiBaseUrl(undefined), DEFAULT_DATASET_REVIEW_API_BASE_URL);
  assert.equal(resolveDatasetReviewApiBaseUrl(' http://localhost:8000/ '), 'http://localhost:8000');
});

test('requests the exact backend status URL without sending an admin token', async () => {
  let requestUrl = '';
  let requestInit;
  const result = await requestDatasetReviewStatus(async (url, init) => {
    requestUrl = String(url);
    requestInit = init;
    return new Response(JSON.stringify(enabledStatus), { status: 200, headers: { 'content-type': 'application/json' } });
  }, 'http://127.0.0.1:8000');
  assert.equal(requestUrl, 'http://127.0.0.1:8000/api/v1/dataset-review/status');
  assert.equal(requestInit.headers.Accept, 'application/json');
  assert.equal(requestInit.headers['X-Dataset-Review-Token'], undefined);
  assert.equal(result.enabled, true);
});

test('reports a backend network failure separately from a disabled response', async () => {
  await assert.rejects(
    requestDatasetReviewStatus(async () => { throw new Error('connection refused'); }, 'http://127.0.0.1:8000'),
    (error) => error instanceof DatasetReviewStatusError
      && error.kind === 'backend_unavailable'
      && error.message === 'Unable to reach dataset review service.',
  );
});

test('times out a status request so loading cannot remain permanent', async () => {
  const result = requestDatasetReviewStatus((_url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }), 'http://127.0.0.1:8000', undefined, 5);
  await assert.rejects(result, (error) => error instanceof DatasetReviewStatusError
    && error.kind === 'backend_unavailable'
    && error.message === 'Dataset review service did not respond in time.');
  assert.equal(DATASET_REVIEW_STATUS_TIMEOUT_MS, 10_000);
});

test('rejects malformed status responses instead of treating them as disabled', () => {
  assert.throws(() => parseDatasetReviewStatus({ enabled: true }), (error) => error instanceof DatasetReviewStatusError && error.kind === 'unexpected');
});

test('keeps admin tokens backend-only and renders an unavailable state on fetch failure', async () => {
  const apiSource = await readFile(new URL('./api.ts', import.meta.url), 'utf8');
  const workspaceSource = await readFile(new URL('../components/dataset-review/dataset-review-workspace.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(apiSource, /DATASET_REVIEW_ADMIN_TOKEN/);
  assert.match(workspaceSource, /serviceState\.kind === 'unavailable'/);
  assert.match(workspaceSource, /requestId !== statusRequestId\.current/);
  assert.doesNotMatch(workspaceSource, /<form\b/);
  assert.doesNotMatch(apiSource, /datasetReviewRequest(?:<[^>]+>)?\(\s*['"]\/?['"]\s*[,)]/s);
  assert.doesNotMatch(workspaceSource, /Dataset review is inactive/);
});
