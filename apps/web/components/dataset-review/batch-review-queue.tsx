'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

import { bulkLabelDatasetReview, bulkReviewSettings, bulkTransitionDatasetReview, fetchDatasetReviewQueue, importDatasetReviewBatch, ApiError } from '@/lib/api';
import type { BulkOperationResponse, DatasetReviewQueueItem, GoldReviewState, ReviewLabel, SourceClaimedLabel } from '@/types/dataset-review';
import { filterQueueItems, pageItems, shortcutAction } from '@/lib/batch-review-queue-utils.mjs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type ActionKind = ReviewLabel | 'approved' | 'rejected' | 'archived' | 'needs_second_review' | 'remove_second_review' | 'set_confidence';

const PAGE_SIZE = 25;
const humanLabels: ReviewLabel[] = ['safe', 'phishing', 'suspicious', 'unable_to_determine'];

function errorMessage(error: unknown) {
  return error instanceof ApiError ? error.message : 'The local review request failed safely.';
}

function labelText(label: string | null) {
  return label ? label.replaceAll('_', ' ') : 'Unlabeled';
}

async function stableOperationKey(prefix: string, value: string) {
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${prefix}-${hex}`;
  }
  return `${prefix}-${value.length}`;
}

export function BatchReviewQueue({ token, reviewerName, onMessage }: { token: string; reviewerName: string; onMessage: (message: string) => void }) {
  const [items, setItems] = useState<DatasetReviewQueueItem[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState(false);
  const [format, setFormat] = useState<'csv' | 'jsonl'>('csv');
  const [batchContent, setBatchContent] = useState('');
  const [confidence, setConfidence] = useState('0.9');
  const [pendingAction, setPendingAction] = useState<ActionKind | null>(null);
  const [filters, setFilters] = useState({ sourceLabel: '', humanLabel: '', state: '', language: '', sourceDataset: '', campaign: '', duplicateStatus: '', secondReviewRequired: '', search: '' });

  const loadQueue = useCallback(async () => {
    if (!token) return;
    setBusy(true);
    try {
      const result = await fetchDatasetReviewQueue(token, { page: 1, page_size: 100 });
      setItems(result.items);
      setPage(1);
    } catch (error) {
      onMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }, [onMessage, token]);

  useEffect(() => { void loadQueue(); }, [loadQueue]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const isTextEntry = Boolean(target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
      if (event.key === 'Escape') {
        if (pendingAction) setPendingAction(null); else setSelected(new Set());
        return;
      }
      const action = shortcutAction(event.key, { isTextEntry, isContentEditable: Boolean(target?.isContentEditable), isBrowserShortcut: event.ctrlKey || event.metaKey || event.altKey });
      if (action && selected.size > 0) {
        event.preventDefault();
        setPendingAction(action as ActionKind);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [pendingAction, selected]);

  const filteredItems = useMemo(() => filterQueueItems(items, filters) as DatasetReviewQueueItem[], [filters, items]);
  const visibleItems = useMemo(() => pageItems(filteredItems, page, PAGE_SIZE) as DatasetReviewQueueItem[], [filteredItems, page]);
  const pageCount = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE));
  const selectedItems = useMemo(() => items.filter((item) => selected.has(item.item_id)), [items, selected]);

  const setFilter = (name: keyof typeof filters, value: string) => { setFilters((current) => ({ ...current, [name]: value })); setPage(1); };
  const toggle = (id: string, checked: boolean) => setSelected((current) => { const next = new Set(current); if (checked) next.add(id); else next.delete(id); return next; });
  const selectVisible = (checked: boolean) => setSelected((current) => { const next = new Set(current); visibleItems.forEach((item) => checked ? next.add(item.item_id) : next.delete(item.item_id)); return next; });

  const importBatch = async () => {
    if (!token || !reviewerName.trim()) return onMessage('Enter the local admin token and human reviewer name first.');
    if (!batchContent.trim()) return onMessage('Paste a sanitized CSV or JSONL batch before importing.');
    setBusy(true);
    try {
      const batchKey = await stableOperationKey(`ui-${format}`, batchContent);
      const result = await importDatasetReviewBatch({ format, content: batchContent, imported_by: reviewerName.trim(), idempotency_key: batchKey, batch_id: batchKey }, token);
      setBatchContent('');
      onMessage(`Imported ${result.imported_count} rows. ${result.duplicate_count} duplicate candidate(s) require inspection; source labels remain advisory.`);
      await loadQueue();
    } catch (error) { onMessage(errorMessage(error)); } finally { setBusy(false); }
  };

  const actionSummary = useMemo(() => {
    if (!pendingAction) return null;
    const sourceDistribution = selectedItems.reduce<Record<string, number>>((counts, item) => { counts[item.source_claimed_label] = (counts[item.source_claimed_label] || 0) + 1; return counts; }, {});
    const mismatch = ['safe', 'phishing', 'suspicious', 'unable_to_determine'].includes(pendingAction) && selectedItems.some((item) => item.source_claimed_label !== pendingAction);
    const lowConfidence = selectedItems.some((item) => (item.confidence ?? Number(confidence)) < 0.75);
    const duplicateCount = selectedItems.filter((item) => item.duplicate_status !== 'clear').length;
    const secondCount = selectedItems.filter((item) => item.second_review_required && !item.second_review_complete).length;
    return { sourceDistribution, mismatch, lowConfidence, duplicateCount, secondCount };
  }, [confidence, pendingAction, selectedItems]);

  const runBulkAction = async () => {
    if (!pendingAction || !reviewerName.trim() || selectedItems.length === 0) return;
    setBusy(true);
    let result: BulkOperationResponse;
    const ids = selectedItems.map((item) => item.item_id);
    try {
      const operationKey = await stableOperationKey(`ui-${pendingAction}`, ids.slice().sort().join('|'));
      if (humanLabels.includes(pendingAction as ReviewLabel)) {
        result = await bulkLabelDatasetReview({ item_ids: ids, label: pendingAction as ReviewLabel, reviewer_name: reviewerName.trim(), confidence: Number(confidence), requires_second_review: false, reason: `Human confirmed bulk label: ${pendingAction}.`, idempotency_key: operationKey }, token);
      } else if (pendingAction === 'set_confidence') {
        result = await bulkReviewSettings({ item_ids: ids, reviewer_name: reviewerName.trim(), confidence: Number(confidence), reason: 'Human updated confidence for selected reviews.', idempotency_key: operationKey }, token);
      } else if (pendingAction === 'needs_second_review' || pendingAction === 'remove_second_review') {
        result = await bulkReviewSettings({ item_ids: ids, reviewer_name: reviewerName.trim(), requires_second_review: pendingAction === 'needs_second_review', reason: pendingAction === 'needs_second_review' ? 'Human required a second review.' : 'Human removed the second-review requirement.', idempotency_key: operationKey }, token);
      } else {
        result = await bulkTransitionDatasetReview({ item_ids: ids, new_state: pendingAction as GoldReviewState, reviewer_name: reviewerName.trim(), reason: `Human bulk transition to ${pendingAction}.`, allow_partial: false, idempotency_key: operationKey }, token);
      }
      const suffix = result.failures.length ? ` ${result.failures.length} item(s) were skipped.` : '';
      onMessage(`${result.affected_count} item(s) affected. ${result.approved_count} approved.${suffix}`);
      setPendingAction(null); setSelected(new Set()); await loadQueue();
    } catch (error) { onMessage(errorMessage(error)); } finally { setBusy(false); }
  };

  const visibleSelected = visibleItems.length > 0 && visibleItems.every((item) => selected.has(item.item_id));
  return (
    <Card>
      <CardHeader><CardTitle className="flex flex-wrap items-center justify-between gap-3"><span>Batch review queue</span><Badge variant="outline">{items.length} loaded / 100 page limit</Badge></CardTitle></CardHeader>
      <CardContent className="space-y-5">
        <Alert><AlertTitle>Human confirmation required</AlertTitle><AlertDescription>Source claims are provenance only. Review sanitized previews, select verified rows, and confirm every bulk operation. Raw email content, complete addresses, headers, URLs, and attachment contents are not accepted or rendered.</AlertDescription></Alert>

        <section aria-labelledby="batch-import-heading" className="space-y-3 rounded-lg border border-border p-4">
          <div><h2 id="batch-import-heading" className="font-semibold">Import a sanitized batch</h2><p className="text-xs text-muted-foreground">Default limit: 100 rows. Use one JSON object per JSONL line or a CSV header plus rows.</p></div>
          <div className="grid gap-3 sm:grid-cols-[180px_1fr]"><div><Label htmlFor="batch-format">Format</Label><select id="batch-format" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={format} onChange={(event) => setFormat(event.target.value as 'csv' | 'jsonl')}><option value="csv">CSV</option><option value="jsonl">JSONL</option></select></div><div><Label htmlFor="batch-content">Sanitized batch content</Label><textarea id="batch-content" rows={5} value={batchContent} onChange={(event) => setBatchContent(event.target.value)} className="mt-1 flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm" placeholder={format === 'csv' ? 'source_sample_id,source_dataset,source_claimed_label,subject,body_excerpt\nsafe-001,synthetic,safe,Weekly notice,Review this notice' : '{"source_sample_id":"safe-001","source_dataset":"synthetic","source_claimed_label":"safe","subject":"Weekly notice","body_excerpt":"Review this notice"}'} /></div></div>
          <Button type="button" onClick={() => void importBatch()} disabled={busy || !token}>Import batch</Button>
        </section>

        <section aria-labelledby="queue-filters-heading" className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><h2 id="queue-filters-heading" className="font-semibold">Review and filter</h2><span className="text-sm text-muted-foreground">{selected.size} selected · {filteredItems.length} visible</span></div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Input aria-label="Search sample, source ID, or campaign" placeholder="Search sample / campaign" value={filters.search} onChange={(event) => setFilter('search', event.target.value)} />
            <select aria-label="Source label filter" className="flex h-10 rounded-md border border-input bg-background px-3 text-sm" value={filters.sourceLabel} onChange={(event) => setFilter('sourceLabel', event.target.value)}><option value="">All source claims</option>{(['safe', 'phishing', 'suspicious', 'unknown'] as SourceClaimedLabel[]).map((value) => <option key={value} value={value}>{labelText(value)}</option>)}</select>
            <select aria-label="Human label filter" className="flex h-10 rounded-md border border-input bg-background px-3 text-sm" value={filters.humanLabel} onChange={(event) => setFilter('humanLabel', event.target.value)}><option value="">All human labels</option>{humanLabels.map((value) => <option key={value} value={value}>{labelText(value)}</option>)}</select>
            <select aria-label="State filter" className="flex h-10 rounded-md border border-input bg-background px-3 text-sm" value={filters.state} onChange={(event) => setFilter('state', event.target.value)}><option value="">All states</option>{(['pending', 'reviewed', 'needs_second_review', 'approved', 'rejected', 'archived'] as GoldReviewState[]).map((value) => <option key={value} value={value}>{labelText(value)}</option>)}</select>
            <Input aria-label="Language filter" placeholder="Language" value={filters.language} onChange={(event) => setFilter('language', event.target.value)} />
            <Input aria-label="Source dataset filter" placeholder="Source dataset" value={filters.sourceDataset} onChange={(event) => setFilter('sourceDataset', event.target.value)} />
            <Input aria-label="Campaign filter" placeholder="Campaign" value={filters.campaign} onChange={(event) => setFilter('campaign', event.target.value)} />
            <select aria-label="Duplicate filter" className="flex h-10 rounded-md border border-input bg-background px-3 text-sm" value={filters.duplicateStatus} onChange={(event) => setFilter('duplicateStatus', event.target.value)}><option value="">All duplicate states</option><option value="clear">Clear</option><option value="duplicate">Duplicate flagged</option></select>
            <select aria-label="Second review filter" className="flex h-10 rounded-md border border-input bg-background px-3 text-sm" value={filters.secondReviewRequired} onChange={(event) => setFilter('secondReviewRequired', event.target.value)}><option value="">Second review: all</option><option value="true">Required</option><option value="false">Not required</option></select>
          </div>
        </section>

        <div className="flex flex-wrap items-center gap-2 rounded-lg bg-surface-muted p-3"><label className="flex items-center gap-2 text-sm"><input type="checkbox" aria-label="Select all visible" checked={visibleSelected} onChange={(event) => selectVisible(event.target.checked)} />Select all visible</label><Button type="button" variant="outline" size="sm" onClick={() => setSelected(new Set())}>Clear selection</Button><span className="text-xs text-muted-foreground">Shortcuts: S safe · P phishing · U unable · A approve · R second review · Esc clear/close</span></div>

        <div className="overflow-x-auto rounded-lg border border-border"><table className="w-full min-w-[950px] text-left text-sm"><thead className="bg-surface-muted text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="p-3">Select</th><th className="p-3">Sample</th><th className="p-3">Source claim</th><th className="p-3">Human label</th><th className="p-3">State</th><th className="p-3">Confidence</th><th className="p-3">Duplicate / second review</th><th className="p-3">Preview</th></tr></thead><tbody>{visibleItems.map((item) => <tr key={item.item_id} className="border-t border-border align-top"><td className="p-3"><input type="checkbox" aria-label={`Select ${item.source_sample_id}`} checked={selected.has(item.item_id)} onChange={(event) => toggle(item.item_id, event.target.checked)} /></td><td className="p-3"><div className="font-medium">{item.source_sample_id}</div><div className="text-xs text-muted-foreground">{item.source_dataset} · {item.language} · {item.campaign_id}</div></td><td className="p-3"><Badge variant="outline">Source claims: {labelText(item.source_claimed_label)}</Badge></td><td className="p-3">{labelText(item.current_human_label)}</td><td className="p-3">{labelText(item.state)}</td><td className="p-3">{item.confidence == null ? '—' : item.confidence.toFixed(2)}</td><td className="p-3"><div>{item.duplicate_status === 'clear' ? 'Clear' : `Duplicate: ${item.duplicate_reasons.join(', ')}`}</div><div>{item.second_review_required ? (item.second_review_complete ? 'Second review complete' : 'Second review required') : 'No second review'}</div></td><td className="p-3"><details><summary className="cursor-pointer text-primary">Show sanitized details</summary><div className="mt-2 max-w-sm space-y-1 text-xs"><p><span className="text-muted-foreground">Subject:</span> {item.subject_preview || '—'}</p><p><span className="text-muted-foreground">Body excerpt:</span> {item.body_excerpt || '—'}</p><p><span className="text-muted-foreground">Domains:</span> {[item.sender_domain, item.reply_to_domain, ...item.url_domains].filter(Boolean).join(', ') || '—'}</p><p><span className="text-muted-foreground">Auth:</span> {item.authentication_summary.join('; ') || '—'}</p><p><span className="text-muted-foreground">Attachments:</span> {item.attachment_metadata || 'none'}</p></div></details></td></tr>)}</tbody></table>{visibleItems.length === 0 && <p className="p-6 text-center text-sm text-muted-foreground">No queue rows match the current filters.</p>}</div>

        <div className="flex flex-wrap items-center justify-between gap-3"><div className="flex gap-2"><Button type="button" variant="outline" size="sm" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={page <= 1}>Previous</Button><span className="self-center text-sm text-muted-foreground">Page {page} of {pageCount}</span><Button type="button" variant="outline" size="sm" onClick={() => setPage((value) => Math.min(pageCount, value + 1))} disabled={page >= pageCount}>Next</Button></div><div className="flex flex-wrap gap-2"><Input aria-label="Bulk confidence" className="w-24" type="number" min="0" max="1" step="0.01" value={confidence} onChange={(event) => setConfidence(event.target.value)} /><Button type="button" onClick={() => setPendingAction('safe')} disabled={busy || selected.size === 0}>Mark Safe</Button><Button type="button" onClick={() => setPendingAction('phishing')} disabled={busy || selected.size === 0}>Mark Phishing</Button><Button type="button" variant="outline" onClick={() => setPendingAction('suspicious')} disabled={busy || selected.size === 0}>Mark Suspicious</Button><Button type="button" variant="outline" onClick={() => setPendingAction('unable_to_determine')} disabled={busy || selected.size === 0}>Unable to Determine</Button><Button type="button" variant="outline" onClick={() => setPendingAction('set_confidence')} disabled={busy || selected.size === 0}>Set confidence</Button><Button type="button" variant="outline" onClick={() => setPendingAction('needs_second_review')} disabled={busy || selected.size === 0}>Require second review</Button><Button type="button" variant="outline" onClick={() => setPendingAction('remove_second_review')} disabled={busy || selected.size === 0}>Remove second review</Button><Button type="button" onClick={() => setPendingAction('approved')} disabled={busy || selected.size === 0}>Approve selected</Button><Button type="button" variant="outline" onClick={() => setPendingAction('rejected')} disabled={busy || selected.size === 0}>Reject selected</Button><Button type="button" variant="outline" onClick={() => setPendingAction('archived')} disabled={busy || selected.size === 0}>Archive selected</Button></div></div>

        {pendingAction && actionSummary && <div role="dialog" aria-modal="true" aria-labelledby="bulk-confirm-title" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"><div className="w-full max-w-lg space-y-4 rounded-lg border border-border bg-background p-5 shadow-xl"><h2 id="bulk-confirm-title" className="text-lg font-semibold">Confirm bulk action</h2><p className="text-sm">Apply <strong>{labelText(pendingAction)}</strong> to <strong>{selectedItems.length}</strong> selected item(s)?</p><p className="text-xs text-muted-foreground">Source-label distribution: {Object.entries(actionSummary.sourceDistribution).map(([key, count]) => `${key} ${count}`).join(' · ') || 'none'}</p>{actionSummary.mismatch && <Alert><AlertTitle>Source-label mismatch</AlertTitle><AlertDescription>The source claims differ from the selected human target. Human confirmation is still required.</AlertDescription></Alert>}{actionSummary.lowConfidence && <Alert><AlertTitle>Low confidence</AlertTitle><AlertDescription>Confidence is below 0.75. Approval may fail if existing approval policy does not allow it.</AlertDescription></Alert>}{actionSummary.duplicateCount > 0 && <Alert><AlertTitle>Duplicate warning</AlertTitle><AlertDescription>{actionSummary.duplicateCount} selected item(s) are duplicate-flagged and cannot be approved automatically.</AlertDescription></Alert>}{actionSummary.secondCount > 0 && <Alert><AlertTitle>Second review warning</AlertTitle><AlertDescription>{actionSummary.secondCount} selected item(s) still require a second human decision.</AlertDescription></Alert>}<div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={() => setPendingAction(null)}>Cancel</Button><Button type="button" onClick={() => void runBulkAction()} disabled={busy}>Confirm {labelText(pendingAction)}</Button></div></div></div>}
      </CardContent>
    </Card>
  );
}
