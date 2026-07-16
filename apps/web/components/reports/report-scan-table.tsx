'use client';

import { CalendarDays, Mail } from 'lucide-react';

import { ReportActionsMenu } from '@/components/reports/report-actions-menu';
import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface ReportScanTableProps {
  scans: ScanRecord[];
  selectedIds: Set<string>;
  onToggle: (id: string) => void;
  onToggleAll: (ids: string[], selected: boolean) => void;
  onView: (scan: ScanRecord) => void;
  onJson: (scan: ScanRecord) => void;
  onCsv: (scan: ScanRecord) => void;
  onPrint: (scan: ScanRecord) => void;
}

function formatDate(timestamp: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
}

function TruncatedValue({ value }: { value: string }) {
  return <Tooltip><TooltipTrigger asChild><span className="block min-w-0 truncate" tabIndex={0}>{value}</span></TooltipTrigger><TooltipContent className="max-w-sm break-words border-slate-700 bg-slate-950 text-slate-200">{value}</TooltipContent></Tooltip>;
}

export function ReportScanTable({ scans, selectedIds, onToggle, onToggleAll, onView, onJson, onCsv, onPrint }: ReportScanTableProps) {
  const ids = scans.map((scan) => scan.id);
  const allSelected = ids.length > 0 && ids.every((id) => selectedIds.has(id));

  return (
    <TooltipProvider delayDuration={300}>
      <div className="divide-y divide-slate-800 md:hidden">
        <label className="flex items-center gap-3 bg-slate-950/40 px-4 py-3 text-xs text-slate-400"><input type="checkbox" checked={allSelected} onChange={(event) => onToggleAll(ids, event.target.checked)} aria-label="Select all visible scans" className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" />Select all visible reports</label>
        {scans.map((scan) => <article key={scan.id} className={cn('p-4', selectedIds.has(scan.id) && 'bg-blue-500/5')}><div className="flex items-start gap-3"><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="mt-1 h-4 w-4 shrink-0 rounded border-slate-600 bg-slate-950 accent-blue-600" /><button type="button" onClick={() => onView(scan)} className="min-w-0 flex-1 text-left"><p className="truncate text-sm font-semibold text-slate-200">{scan.subject}</p><p className="mt-1 flex items-center gap-1.5 truncate text-xs text-slate-500"><Mail className="h-3 w-3" aria-hidden="true" />{scan.sender}</p></button><ReportActionsMenu scan={scan} onView={onView} onJson={onJson} onCsv={onCsv} onPrint={onPrint} /></div><div className="mt-4 flex flex-wrap items-center gap-2 pl-7"><ClassificationBadge classification={scan.classification} /><span className={cn('text-sm font-semibold tabular-nums', scan.riskScore >= 70 ? 'text-rose-300' : scan.riskScore >= 30 ? 'text-amber-300' : 'text-emerald-300')}>{scan.riskScore}/100</span><span className="ml-auto flex items-center gap-1 text-xs text-slate-500"><CalendarDays className="h-3 w-3" aria-hidden="true" />{formatDate(scan.timestamp)}</span></div></article>)}
      </div>

      <div className="hidden overflow-x-auto md:block">
        <Table className="min-w-[780px] table-fixed">
          <colgroup><col className="w-12" /><col /><col className="w-48" /><col className="w-32" /><col className="w-24" /><col className="w-48" /><col className="w-16" /></colgroup>
          <TableHeader className="bg-slate-950/70"><TableRow className="border-slate-800 hover:bg-transparent"><TableHead><input type="checkbox" checked={allSelected} onChange={(event) => onToggleAll(ids, event.target.checked)} aria-label="Select all visible scans" className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableHead><TableHead className="text-slate-400">Subject</TableHead><TableHead className="text-slate-400">Sender</TableHead><TableHead className="text-slate-400">Verdict</TableHead><TableHead className="text-slate-400">Risk</TableHead><TableHead className="text-slate-400">Analyzed</TableHead><TableHead className="text-right text-slate-400"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader>
          <TableBody>{scans.map((scan) => <TableRow key={scan.id} data-state={selectedIds.has(scan.id) ? 'selected' : undefined} className="border-slate-800 hover:bg-slate-800/40"><TableCell><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableCell><TableCell className="min-w-0 font-medium text-slate-200"><button type="button" onClick={() => onView(scan)} className="block w-full text-left hover:text-blue-300"><TruncatedValue value={scan.subject} /></button></TableCell><TableCell className="min-w-0 text-slate-400"><TruncatedValue value={scan.sender} /></TableCell><TableCell><ClassificationBadge classification={scan.classification} /></TableCell><TableCell className={cn('font-semibold tabular-nums', scan.riskScore >= 70 ? 'text-rose-300' : scan.riskScore >= 30 ? 'text-amber-300' : 'text-emerald-300')}>{scan.riskScore}/100</TableCell><TableCell className="whitespace-nowrap text-xs text-slate-400">{formatDate(scan.timestamp)}</TableCell><TableCell className="text-right"><ReportActionsMenu scan={scan} onView={onView} onJson={onJson} onCsv={onCsv} onPrint={onPrint} /></TableCell></TableRow>)}</TableBody>
        </Table>
      </div>
    </TooltipProvider>
  );
}
