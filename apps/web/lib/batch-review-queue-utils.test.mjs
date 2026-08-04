import test from 'node:test';
import assert from 'node:assert/strict';

import { filterQueueItems, pageItems, shortcutAction, toggleSelection } from './batch-review-queue-utils.mjs';

const items = [
  { item_id: '1', source_sample_id: 'safe-1', batch_id: 'a', campaign_id: 'weekly', source_claimed_label: 'safe', current_human_label: null, state: 'pending', language: 'en', source_dataset: 'synthetic', duplicate_status: 'clear', second_review_required: false },
  { item_id: '2', source_sample_id: 'phish-1', batch_id: 'b', campaign_id: 'urgent', source_claimed_label: 'phishing', current_human_label: 'phishing', state: 'reviewed', language: 'en', source_dataset: 'synthetic', duplicate_status: 'duplicate', second_review_required: true },
];

test('queue filters and search are deterministic', () => {
  assert.equal(filterQueueItems(items, { sourceLabel: 'phishing', humanLabel: '', state: '', language: '', sourceDataset: '', campaign: '', duplicateStatus: '', secondReviewRequired: '', search: '' }).length, 1);
  assert.equal(filterQueueItems(items, { sourceLabel: '', humanLabel: '', state: '', language: '', sourceDataset: '', campaign: '', duplicateStatus: '', secondReviewRequired: '', search: 'weekly' }).length, 1);
});

test('pagination and selection preserve stable item IDs', () => {
  assert.deepEqual(pageItems(items, 2, 1).map((item) => item.item_id), ['2']);
  assert.deepEqual([...toggleSelection(new Set(['1']), '2', true)].sort(), ['1', '2']);
  assert.deepEqual([...toggleSelection(new Set(['1', '2']), '1', false)], ['2']);
});

test('shortcuts require non-text focus', () => {
  assert.equal(shortcutAction('s'), 'safe');
  assert.equal(shortcutAction('a', { isTextEntry: true }), null);
  assert.equal(shortcutAction('x'), null);
});
