'use client';

import { ReportActionsMenu } from '@/components/reports/report-actions-menu';
import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
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

function TruncatedValue({ value }: { value: string }) {
  return <Tooltip><TooltipTrigger asChild><span className="block min-w-0 truncate" tabIndex={0}>{value}</span></TooltipTrigger><TooltipContent className="max-w-sm break-words border-slate-700 bg-slate-950 text-slate-200">{value}</TooltipContent></Tooltip>;
}

export function ReportScanTable({ scans, selectedIds, onToggle, onToggleAll, onView, onJson, onCsv, onPrint }: ReportScanTableProps) {
  const ids = scans.map((scan) => scan.id);
  const allSelected = ids.length > 0 && ids.every((id) => selectedIds.has(id));

  return (
    <TooltipProvider delayDuration={300}>
      <Table className="min-w-[640px] table-fixed">
        <colgroup><col className="w-12" /><col /><col className="w-40" /><col className="w-24" /><col className="w-16" /></colgroup>
        <TableHeader className="bg-slate-950/50">
          <TableRow className="border-slate-800 hover:bg-transparent">
            <TableHead><input type="checkbox" checked={allSelected} onChange={(event) => onToggleAll(ids, event.target.checked)} aria-label="Select all visible scans" className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableHead>
            <TableHead className="text-slate-400">Subject</TableHead>
            <TableHead className="sticky right-40 z-10 bg-slate-950 text-slate-400">Classification</TableHead>
            <TableHead className="sticky right-16 z-10 whitespace-nowrap bg-slate-950 text-slate-400">Risk</TableHead>
            <TableHead className="sticky right-0 z-10 bg-slate-950 text-right text-slate-400"><span className="sr-only">Report actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {scans.map((scan) => (
            <TableRow key={scan.id} data-state={selectedIds.has(scan.id) ? 'selected' : undefined} className="border-slate-800 hover:bg-slate-800/40">
              <TableCell><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableCell>
              <TableCell className="min-w-0 font-medium text-slate-200"><TruncatedValue value={scan.subject} /></TableCell>
              <TableCell className="sticky right-40 z-10 bg-slate-900"><ClassificationBadge classification={scan.classification} /></TableCell>
              <TableCell className={scan.riskScore >= 70 ? 'sticky right-16 z-10 bg-slate-900 font-semibold tabular-nums text-rose-300' : scan.riskScore >= 30 ? 'sticky right-16 z-10 bg-slate-900 font-semibold tabular-nums text-amber-300' : 'sticky right-16 z-10 bg-slate-900 font-semibold tabular-nums text-emerald-300'}>{scan.riskScore}/100</TableCell>
              <TableCell className="sticky right-0 z-10 bg-slate-900 text-right"><ReportActionsMenu scan={scan} onView={onView} onJson={onJson} onCsv={onCsv} onPrint={onPrint} /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TooltipProvider>
  );
}
