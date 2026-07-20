'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { Download, FileText, Inbox, Search } from 'lucide-react';

import { ConfirmationDialog } from '@/components/history/confirmation-dialog';
import { ReportPreview } from '@/components/reports/report-preview';
import { ReportScanTable } from '@/components/reports/report-scan-table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { useScanRecords } from '@/hooks/use-scan-records';
import { filterAndSortScans, type ScanHistoryFilter } from '@/lib/scan-history';
import { downloadReports, printScanReport, requiresLargeBatchConfirmation, type ReportExportFormat } from '@/lib/reports';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

const filters: Array<{ value: ScanHistoryFilter; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'safe', label: 'Safe' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'phishing', label: 'Phishing' },
];

function LoadingReports() {
  return <div className="space-y-3 p-5" aria-busy="true" aria-label="Loading reports">{Array.from({ length: 6 }, (_, index) => <Skeleton key={index} className="h-14 w-full bg-surface-muted" />)}</div>;
}

export function ReportsWorkspace() {
  const { scans, isLoaded } = useScanRecords();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ScanHistoryFilter>('all');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [pendingExport, setPendingExport] = useState<{ scans: ScanRecord[]; format: ReportExportFormat } | null>(null);

  const visibleScans = useMemo(() => filterAndSortScans(scans, query, filter, 'newest'), [filter, query, scans]);
  const selectedScans = useMemo(() => scans.filter((scan) => selectedIds.has(scan.id)), [scans, selectedIds]);
  const previewScan = previewId ? scans.find((scan) => scan.id === previewId) ?? null : null;

  useEffect(() => {
    const availableIds = new Set(scans.map((scan) => scan.id));
    setSelectedIds((current) => {
      const next = new Set([...current].filter((id) => availableIds.has(id)));
      return next.size === current.size ? current : next;
    });
    if (previewId && !availableIds.has(previewId)) setPreviewId(null);
  }, [previewId, scans]);

  const closePreview = useCallback(() => setPreviewId(null), []);
  const closeConfirmation = useCallback(() => setPendingExport(null), []);

  const toggleSelected = (id: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = (ids: string[], selected: boolean) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of ids) {
        if (selected) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  const exportScans = (records: ScanRecord[], format: ReportExportFormat, confirmLargeBatch = false) => {
    if (records.length === 0) return;
    if (confirmLargeBatch && requiresLargeBatchConfirmation(records.length)) {
      setPendingExport({ scans: records, format });
      return;
    }
    downloadReports(records, format);
  };

  const confirmBatchExport = () => {
    if (!pendingExport) return;
    downloadReports(pendingExport.scans, pendingExport.format);
    setPendingExport(null);
  };

  return (
    <div className="reports-surface space-y-6">
      <header>
        <div className="mb-3 flex items-center gap-2"><Badge variant="outline" className="border-input bg-surface text-muted-foreground"><FileText className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />Browser-generated reports</Badge></div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">Reports</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Preview, export, and print investigation reports from locally stored scan records.</p>
      </header>

      {!isLoaded ? (
        <Card className="border-border bg-surface/80"><LoadingReports /></Card>
      ) : scans.length === 0 ? (
        <Card className="flex min-h-[430px] items-center justify-center border-dashed border-border bg-surface/40">
          <CardContent className="max-w-md p-8 text-center">
            <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-border bg-background text-foreground0"><Inbox size={26} aria-hidden="true" /></span>
            <h2 className="mt-5 text-lg font-semibold text-foreground">No reports available</h2>
            <p className="mt-2 text-sm leading-6 text-foreground0">Reports are generated from locally stored analyses. Analyze an email to create your first report.</p>
            <Button asChild className="mt-6 bg-primary text-primary-foreground hover:bg-primary"><Link href="/analyze">Analyze your first email</Link></Button>
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden border-border bg-surface/80">
          <CardHeader className="sticky top-16 z-20 border-b border-border bg-surface/95 pb-5 backdrop-blur">
            <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
              <div><CardTitle className="text-base text-foreground">Stored scans</CardTitle><CardDescription className="mt-1 text-muted-foreground">{visibleScans.length} of {scans.length} scans · {selectedIds.size} selected</CardDescription></div>
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="outline" size="sm" disabled={selectedScans.length === 0} onClick={() => exportScans(selectedScans, 'json', true)} className="border-input bg-background text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Download aria-hidden="true" />Export selected JSON</Button>
                <Button type="button" variant="outline" size="sm" disabled={selectedScans.length === 0} onClick={() => exportScans(selectedScans, 'csv', true)} className="border-input bg-background text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Download aria-hidden="true" />Export selected CSV</Button>
              </div>
            </div>
            <div className="mt-4 flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="relative min-w-0 flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground0" aria-hidden="true" />
                <Input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search subject or sender…" aria-label="Search report scans by subject or sender" className="border-input bg-background pl-9 text-foreground placeholder:text-muted-foreground" />
              </div>
              <div className="flex flex-wrap items-center gap-1 rounded-md border border-input bg-background p-1" aria-label="Filter report scans by classification">
                {filters.map((item) => <Button key={item.value} type="button" variant="ghost" size="sm" onClick={() => setFilter(item.value)} className={cn('h-8 px-3 text-xs', filter === item.value ? 'bg-surface-muted text-primary hover:bg-surface-muted' : 'text-muted-foreground hover:bg-surface-muted hover:text-foreground')}>{item.label}</Button>)}
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {visibleScans.length === 0 ? (
              <div className="flex min-h-80 flex-col items-center justify-center px-6 text-center"><Search className="h-8 w-8 text-muted-foreground" aria-hidden="true" /><p className="mt-3 text-sm font-medium text-foreground">No matching scans</p><p className="mt-1 text-xs text-foreground0">Adjust your search or classification filter.</p><Button type="button" variant="ghost" size="sm" onClick={() => { setQuery(''); setFilter('all'); }} className="mt-4 text-primary hover:bg-surface-muted hover:text-primary">Reset filters</Button></div>
            ) : (
              <ReportScanTable scans={visibleScans} selectedIds={selectedIds} onToggle={toggleSelected} onToggleAll={toggleAll} onView={(scan) => setPreviewId(scan.id)} onJson={(scan) => exportScans([scan], 'json')} onCsv={(scan) => exportScans([scan], 'csv')} onPrint={printScanReport} />
            )}
          </CardContent>
        </Card>
      )}

      {previewScan && <ReportPreview scan={previewScan} onClose={closePreview} onJson={() => exportScans([previewScan], 'json')} onCsv={() => exportScans([previewScan], 'csv')} onPrint={() => printScanReport(previewScan)} />}
      <ConfirmationDialog open={pendingExport !== null} title="Export large report batch?" description={`You are about to generate ${pendingExport?.scans.length ?? 0} ${pendingExport?.format.toUpperCase() ?? ''} reports in browser memory. Continue with the download?`} confirmLabel="Generate export" tone="primary" onCancel={closeConfirmation} onConfirm={confirmBatchExport} />
    </div>
  );
}
