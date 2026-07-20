'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { ChevronLeft, ChevronRight, Filter, History, Inbox, Search, Trash2 } from 'lucide-react';

import { ConfirmationDialog } from '@/components/history/confirmation-dialog';
import { ScanDetailPanel } from '@/components/history/scan-detail-panel';
import { ScanHistoryTable } from '@/components/history/scan-history-table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { useScanRecords } from '@/hooks/use-scan-records';
import { usePreferences } from '@/hooks/use-preferences';
import { filterAndSortScans, paginateScans, type ScanHistoryFilter, type ScanHistorySortOrder } from '@/lib/scan-history';
import { clearScans, deleteScan, deleteScans } from '@/lib/scan-store';
import { cn } from '@/lib/utils';

type PendingDelete = { kind: 'single' | 'selected'; ids: string[] } | { kind: 'all'; ids: [] };

const PAGE_SIZE = 10;
const filters: Array<{ value: ScanHistoryFilter; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'safe', label: 'Safe' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'phishing', label: 'Phishing' },
];

function LoadingTable() {
  return <div className="space-y-3 p-5" aria-busy="true" aria-label="Loading scan history">{Array.from({ length: 6 }, (_, index) => <Skeleton key={index} className="h-14 w-full bg-surface-muted" />)}</div>;
}

export function ScanHistory() {
  const { scans, isLoaded } = useScanRecords();
  const { preferences, isLoaded: preferencesLoaded } = usePreferences();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ScanHistoryFilter>('all');
  const [sortOrder, setSortOrder] = useState<ScanHistorySortOrder>('newest');
  const [page, setPage] = useState(1);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [openScanId, setOpenScanId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<PendingDelete | null>(null);

  const filteredScans = useMemo(() => filterAndSortScans(scans, query, filter, sortOrder), [filter, query, scans, sortOrder]);

  const { currentPage, pageCount, scans: pageScans } = paginateScans(filteredScans, page, PAGE_SIZE);
  const selectedScan = openScanId ? scans.find((scan) => scan.id === openScanId) ?? null : null;

  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  useEffect(() => {
    if (preferencesLoaded) {
      setSortOrder(preferences.defaultHistorySortOrder);
      setPage(1);
    }
  }, [preferences.defaultHistorySortOrder, preferencesLoaded]);

  useEffect(() => {
    const availableIds = new Set(scans.map((scan) => scan.id));
    setSelectedIds((current) => {
      const next = new Set([...current].filter((id) => availableIds.has(id)));
      return next.size === current.size ? current : next;
    });
    if (openScanId && !availableIds.has(openScanId)) setOpenScanId(null);
  }, [openScanId, scans]);

  const closeDetail = useCallback(() => setOpenScanId(null), []);
  const closeConfirmation = useCallback(() => setPendingDelete(null), []);

  const updateFilter = (value: ScanHistoryFilter) => {
    setFilter(value);
    setPage(1);
  };

  const toggleSelected = (id: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePage = (ids: string[], selected: boolean) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of ids) {
        if (selected) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  const confirmDeletion = () => {
    if (!pendingDelete) return;
    if (pendingDelete.kind === 'all') clearScans();
    else if (pendingDelete.kind === 'single') deleteScan(pendingDelete.ids[0]);
    else deleteScans(pendingDelete.ids);
    setSelectedIds(new Set());
    if (pendingDelete.kind === 'all' || pendingDelete.ids.includes(openScanId ?? '')) setOpenScanId(null);
    setPendingDelete(null);
  };

  const requestClearHistory = () => {
    if (preferences.confirmBeforeClearingHistory) {
      setPendingDelete({ kind: 'all', ids: [] });
      return;
    }
    clearScans();
    setSelectedIds(new Set());
    setOpenScanId(null);
  };

  const resetControls = () => {
    setQuery('');
    setFilter('all');
    setSortOrder(preferences.defaultHistorySortOrder);
    setPage(1);
  };

  const confirmationCopy = pendingDelete?.kind === 'all'
    ? { title: 'Clear entire scan history?', description: `This will permanently remove all ${scans.length} locally stored scan records. This action cannot be undone.`, label: 'Clear history' }
    : pendingDelete?.kind === 'selected'
      ? { title: `Delete ${pendingDelete.ids.length} selected scans?`, description: 'The selected records will be permanently removed from this browser and dashboard statistics will update immediately.', label: 'Delete selected' }
      : { title: 'Delete this scan?', description: 'This scan record will be permanently removed from this browser and dashboard statistics will update immediately.', label: 'Delete scan' };

  return (
    <div className="history-surface space-y-6">
      <header className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2">
            <Badge variant="outline" className="border-input bg-surface text-muted-foreground"><History className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />Local investigation archive</Badge>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">Scan History</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Search, triage, and review every email analysis stored in this browser.</p>
        </div>
        <Button type="button" variant="outline" disabled={!isLoaded || scans.length === 0} onClick={requestClearHistory} className="border-input bg-surface text-muted-foreground hover:bg-danger/10 hover:text-danger"><Trash2 aria-hidden="true" />Clear history</Button>
      </header>

      {!isLoaded ? (
        <Card className="border-border bg-surface/80"><LoadingTable /></Card>
      ) : scans.length === 0 ? (
        <Card className="flex min-h-[430px] items-center justify-center border-dashed border-border bg-surface/40">
          <CardContent className="max-w-md p-8 text-center">
            <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-border bg-background text-foreground0"><Inbox size={26} aria-hidden="true" /></span>
            <h2 className="mt-5 text-lg font-semibold text-foreground">No analyses yet</h2>
            <p className="mt-2 text-sm leading-6 text-foreground0">Analyze an email to create your first locally stored investigation record.</p>
            <Button asChild className="mt-6 bg-primary text-primary-foreground hover:bg-primary"><Link href="/analyze">Analyze your first email</Link></Button>
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden border-border bg-surface/80">
          <CardHeader className="sticky top-16 z-20 border-b border-border bg-surface/95 pb-5 backdrop-blur">
            <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
              <div><CardTitle className="text-base text-foreground">Investigation records</CardTitle><CardDescription className="mt-1 text-muted-foreground">{filteredScans.length} of {scans.length} scans</CardDescription></div>
              {selectedIds.size > 0 && <Button type="button" size="sm" onClick={() => setPendingDelete({ kind: 'selected', ids: [...selectedIds] })} className="bg-danger text-primary-foreground hover:bg-danger"><Trash2 aria-hidden="true" />Delete selected ({selectedIds.size})</Button>}
            </div>

            <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(260px,1fr)_auto_210px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground0" aria-hidden="true" />
                <Input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="Search subject or sender…" aria-label="Search scans by subject or sender" className="border-input bg-background pl-9 text-foreground placeholder:text-muted-foreground" />
              </div>
              <div className="flex flex-wrap items-center gap-1 rounded-md border border-input bg-background p-1" aria-label="Filter scans by classification">
                <Filter className="mx-2 h-4 w-4 text-foreground0" aria-hidden="true" />
                {filters.map((item) => <Button key={item.value} type="button" size="sm" variant="ghost" onClick={() => updateFilter(item.value)} className={cn('h-8 px-3 text-xs', filter === item.value ? 'bg-surface-muted text-primary hover:bg-surface-muted' : 'text-muted-foreground hover:bg-surface-muted hover:text-foreground')}>{item.label}</Button>)}
              </div>
              <select value={sortOrder} onChange={(event) => { setSortOrder(event.target.value as ScanHistorySortOrder); setPage(1); }} aria-label="Sort scan history" className="h-10 rounded-md border border-input bg-background px-3 text-sm text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring/20">
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="highest-risk">Highest risk</option>
                <option value="lowest-risk">Lowest risk</option>
              </select>
            </div>
          </CardHeader>

          <CardContent className="p-0">
            {filteredScans.length === 0 ? (
              <div className="flex min-h-80 flex-col items-center justify-center px-6 text-center">
                <Search className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
                <p className="mt-3 text-sm font-medium text-foreground">No matching scans</p>
                <p className="mt-1 text-xs text-foreground0">Adjust your search or classification filter.</p>
                <Button type="button" variant="ghost" size="sm" onClick={resetControls} className="mt-4 text-primary hover:bg-surface-muted hover:text-primary">Reset filters</Button>
              </div>
            ) : (
              <>
                <ScanHistoryTable scans={pageScans} selectedIds={selectedIds} onOpen={setOpenScanId} onDelete={(id) => setPendingDelete({ kind: 'single', ids: [id] })} onToggle={toggleSelected} onTogglePage={togglePage} />
                <div className="flex flex-col items-center justify-between gap-3 border-t border-border px-5 py-4 text-xs text-foreground0 sm:flex-row">
                  <p>Showing {(currentPage - 1) * PAGE_SIZE + 1}–{Math.min(currentPage * PAGE_SIZE, filteredScans.length)} of {filteredScans.length}</p>
                  <div className="flex items-center gap-2">
                    <Button type="button" variant="outline" size="sm" disabled={currentPage === 1} onClick={() => setPage((current) => Math.max(1, current - 1))} className="border-input bg-background text-muted-foreground hover:bg-surface-muted hover:text-foreground"><ChevronLeft aria-hidden="true" />Previous</Button>
                    <span className="px-2 tabular-nums text-muted-foreground">Page {currentPage} of {pageCount}</span>
                    <Button type="button" variant="outline" size="sm" disabled={currentPage === pageCount} onClick={() => setPage((current) => Math.min(pageCount, current + 1))} className="border-input bg-background text-muted-foreground hover:bg-surface-muted hover:text-foreground">Next<ChevronRight aria-hidden="true" /></Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {selectedScan && <ScanDetailPanel scan={selectedScan} onClose={closeDetail} onDelete={(id) => setPendingDelete({ kind: 'single', ids: [id] })} />}
      <ConfirmationDialog open={pendingDelete !== null} title={confirmationCopy.title} description={confirmationCopy.description} confirmLabel={confirmationCopy.label} onCancel={closeConfirmation} onConfirm={confirmDeletion} />
    </div>
  );
}
