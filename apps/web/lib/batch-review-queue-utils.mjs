export function filterQueueItems(items, filters) {
  const query = (filters.search || '').trim().toLowerCase();
  return items.filter((item) => {
    if (filters.sourceLabel && item.source_claimed_label !== filters.sourceLabel) return false;
    if (filters.humanLabel && item.current_human_label !== filters.humanLabel) return false;
    if (filters.state && item.state !== filters.state) return false;
    if (filters.language && item.language !== filters.language) return false;
    if (filters.sourceDataset && item.source_dataset !== filters.sourceDataset) return false;
    if (filters.campaign && item.campaign_id !== filters.campaign) return false;
    if (filters.duplicateStatus && item.duplicate_status !== filters.duplicateStatus) return false;
    if (filters.secondReviewRequired !== '' && String(item.second_review_required) !== filters.secondReviewRequired) return false;
    if (query && ![item.source_sample_id, item.batch_id, item.campaign_id].some((value) => value.toLowerCase().includes(query))) return false;
    return true;
  });
}

export function pageItems(items, page, pageSize) {
  const start = Math.max(0, page - 1) * pageSize;
  return items.slice(start, start + pageSize);
}

export function shortcutAction(key, target = {}) {
  if (target.isTextEntry || target.isContentEditable || target.isBrowserShortcut) return null;
  return ({ s: 'safe', p: 'phishing', u: 'unable_to_determine', a: 'approved', r: 'needs_second_review' })[key.toLowerCase()] || null;
}

export function toggleSelection(selected, itemId, checked) {
  const next = new Set(selected);
  if (checked) next.add(itemId); else next.delete(itemId);
  return next;
}
