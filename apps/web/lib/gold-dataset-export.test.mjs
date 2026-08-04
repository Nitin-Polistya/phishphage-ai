import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  formatGoldExportError,
  safeGoldExportFilename,
  safeGoldExportFiles,
  safeGoldExportLocation,
} from './gold-dataset-export.ts';

test('keeps only repository-relative private export locations', () => {
  assert.equal(safeGoldExportLocation('services/ml/evaluation/private/gold_dataset_reports/'), 'services/ml/evaluation/private/gold_dataset_reports/');
  assert.equal(safeGoldExportLocation('D:\\private\\gold_dataset_reports'), 'private review directory');
  assert.equal(safeGoldExportLocation('/home/user/private/gold_dataset_reports/'), 'private review directory');
  assert.equal(safeGoldExportLocation('services/ml/evaluation/private/../secrets/'), 'private review directory');
});

test('renders only safe export filenames and preserves verified sizes', () => {
  assert.equal(safeGoldExportFilename('gold_dataset_v1.jsonl'), 'gold_dataset_v1.jsonl');
  assert.equal(safeGoldExportFilename('../secret.txt'), 'unavailable filename');
  assert.deepEqual(safeGoldExportFiles([{ filename: 'gold_dataset_v1.jsonl', status: 'written', size_bytes: 42 }]), [
    { filename: 'gold_dataset_v1.jsonl', status: 'written', size_bytes: 42 },
  ]);
});

test('distinguishes export failure categories for reviewers', () => {
  assert.equal(formatGoldExportError({ code: 'authorization_failed' }), 'Export authorization failed. Check the local administrative token.');
  assert.equal(formatGoldExportError({ code: 'no_approved_records' }), 'No approved human-reviewed records are available to export.');
  assert.equal(formatGoldExportError({ code: 'export_storage_failure' }), 'Export storage failed. The local backend could not write all required files.');
  assert.equal(formatGoldExportError({ code: 'export_file_verification_failed' }), 'Export verification failed. One or more required files are missing or unsafe.');
  assert.equal(formatGoldExportError({ kind: 'backend_unavailable' }), 'The local dataset-review backend is unavailable.');
});

test('workspace exposes persistent accessible export states and prevents unsafe path rendering', async () => {
  const workspace = await readFile(new URL('../components/dataset-review/dataset-review-workspace.tsx', import.meta.url), 'utf8');
  const button = await readFile(new URL('../components/ui/button.tsx', import.meta.url), 'utf8');
  assert.match(workspace, /setExportResult\(null\)/);
  assert.match(workspace, /setExporting\(true\)/);
  assert.match(workspace, /Export successful/);
  assert.match(workspace, /exportResult\.exported_count/);
  assert.match(workspace, /safeGoldExportLocation\(exportResult\.output_location\)/);
  assert.match(workspace, /safeGoldExportFiles\(exportResult\.files\)/);
  assert.match(workspace, /aria-live="polite"/);
  assert.match(workspace, /formatGoldExportError/);
  assert.match(workspace, /onClick=\{\(\) => void exportGold\(\)\}/);
  assert.match(workspace, /disabled=\{busy \|\| !token\}/);
  assert.match(button, /type = "button"/);
});
