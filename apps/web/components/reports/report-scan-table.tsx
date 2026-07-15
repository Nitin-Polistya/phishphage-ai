'use client';

import { Download, Eye, Printer } from 'lucide-react';

import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { formatReportDate } from '@/lib/reports';
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
  return <Tooltip><TooltipTrigger asChild><span className="block max-w-64 truncate" tabIndex={0}>{value}</span></TooltipTrigger><TooltipContent className="max-w-sm break-words border-slate-700 bg-slate-950 text-slate-200">{value}</TooltipContent></Tooltip>;
}

export function ReportScanTable({ scans, selectedIds, onToggle, onToggleAll, onView, onJson, onCsv, onPrint }: ReportScanTableProps) {
  const ids = scans.map((scan) => scan.id);
  const allSelected = ids.length > 0 && ids.every((id) => selectedIds.has(id));

  return (
    <TooltipProvider delayDuration={300}>
      <Table>
        <TableHeader className="bg-slate-950/50">
          <TableRow className="border-slate-800 hover:bg-transparent">
            <TableHead className="w-12"><input type="checkbox" checked={allSelected} onChange={(event) => onToggleAll(ids, event.target.checked)} aria-label="Select all visible scans" className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableHead>
            <TableHead className="min-w-64 text-slate-400">Subject</TableHead>
            <TableHead className="min-w-56 text-slate-400">Sender</TableHead>
            <TableHead className="text-slate-400">Classification</TableHead>
            <TableHead className="whitespace-nowrap text-slate-400">Risk</TableHead>
            <TableHead className="min-w-48 whitespace-nowrap text-slate-400">Scan date</TableHead>
            <TableHead className="min-w-[360px] text-right text-slate-400">Report actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {scans.map((scan) => (
            <TableRow key={scan.id} data-state={selectedIds.has(scan.id) ? 'selected' : undefined} className="border-slate-800 hover:bg-slate-800/40">
              <TableCell><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" /></TableCell>
              <TableCell className="font-medium text-slate-200"><TruncatedValue value={scan.subject} /></TableCell>
              <TableCell className="text-slate-400"><TruncatedValue value={scan.sender} /></TableCell>
              <TableCell><ClassificationBadge classification={scan.classification} /></TableCell>
              <TableCell className={scan.riskScore >= 70 ? 'font-semibold tabular-nums text-rose-300' : scan.riskScore >= 30 ? 'font-semibold tabular-nums text-amber-300' : 'font-semibold tabular-nums text-emerald-300'}>{scan.riskScore}/100</TableCell>
              <TableCell className="whitespace-nowrap text-slate-400">{formatReportDate(scan.timestamp)}</TableCell>
              <TableCell>
                <div className="flex justify-end gap-1">
                  <Button type="button" variant="ghost" size="sm" onClick={() => onView(scan)} className="text-slate-400 hover:bg-slate-800 hover:text-white"><Eye aria-hidden="true" />View</Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => onJson(scan)} className="text-slate-400 hover:bg-slate-800 hover:text-white"><Download aria-hidden="true" />JSON</Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => onCsv(scan)} className="text-slate-400 hover:bg-slate-800 hover:text-white"><Download aria-hidden="true" />CSV</Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => onPrint(scan)} className="text-slate-400 hover:bg-slate-800 hover:text-white"><Printer aria-hidden="true" />Print</Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TooltipProvider>
  );
}
