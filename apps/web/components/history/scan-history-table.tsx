'use client';

import { KeyboardEvent, MouseEvent } from 'react';
import { Trash2 } from 'lucide-react';

import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface ScanHistoryTableProps {
  scans: ScanRecord[];
  selectedIds: Set<string>;
  onOpen: (id: string) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string) => void;
  onTogglePage: (ids: string[], selected: boolean) => void;
}

function formatDate(timestamp: string) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp));
}

function TruncatedValue({ children }: { children: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="block max-w-64 truncate" tabIndex={0}>{children}</span>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm break-words border-slate-700 bg-slate-950 text-slate-200">{children}</TooltipContent>
    </Tooltip>
  );
}

export function ScanHistoryTable({ scans, selectedIds, onOpen, onDelete, onToggle, onTogglePage }: ScanHistoryTableProps) {
  const pageIds = scans.map((scan) => scan.id);
  const pageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));

  const openFromKeyboard = (event: KeyboardEvent<HTMLTableRowElement>, id: string) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onOpen(id);
    }
  };

  const stopRowClick = (event: MouseEvent) => event.stopPropagation();

  return (
    <TooltipProvider delayDuration={300}>
      <Table>
        <TableHeader className="bg-slate-950/50">
          <TableRow className="border-slate-800 hover:bg-transparent">
            <TableHead className="w-12">
              <input type="checkbox" checked={pageSelected} onChange={(event) => onTogglePage(pageIds, event.target.checked)} aria-label="Select all scans on this page" className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" />
            </TableHead>
            <TableHead className="min-w-64 text-slate-400">Subject</TableHead>
            <TableHead className="min-w-56 text-slate-400">Sender</TableHead>
            <TableHead className="text-slate-400">Classification</TableHead>
            <TableHead className="whitespace-nowrap text-slate-400">Risk</TableHead>
            <TableHead className="whitespace-nowrap text-slate-400">Confidence</TableHead>
            <TableHead className="min-w-48 whitespace-nowrap text-slate-400">Scanned</TableHead>
            <TableHead className="whitespace-nowrap text-center text-slate-400">Files</TableHead>
            <TableHead className="whitespace-nowrap text-center text-slate-400">URLs</TableHead>
            <TableHead className="w-14"><span className="sr-only">Actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {scans.map((scan) => (
            <TableRow key={scan.id} role="button" tabIndex={0} aria-label={`Open scan details for ${scan.subject}`} data-state={selectedIds.has(scan.id) ? 'selected' : undefined} onClick={() => onOpen(scan.id)} onKeyDown={(event) => openFromKeyboard(event, scan.id)} className="cursor-pointer border-slate-800 transition-colors hover:bg-slate-800/50 focus-visible:bg-slate-800/50 focus-visible:outline-none">
              <TableCell onClick={stopRowClick} onKeyDown={(event) => event.stopPropagation()}>
                <input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600" />
              </TableCell>
              <TableCell className="font-medium text-slate-200"><TruncatedValue>{scan.subject}</TruncatedValue></TableCell>
              <TableCell className="text-slate-400"><TruncatedValue>{scan.sender}</TruncatedValue></TableCell>
              <TableCell><ClassificationBadge classification={scan.classification} /></TableCell>
              <TableCell className={cn('font-semibold tabular-nums', scan.riskScore >= 70 ? 'text-rose-300' : scan.riskScore >= 30 ? 'text-amber-300' : 'text-emerald-300')}>{scan.riskScore}/100</TableCell>
              <TableCell className="tabular-nums text-slate-300">{Math.round(scan.confidence * 100)}%</TableCell>
              <TableCell className="whitespace-nowrap text-slate-400">{formatDate(scan.timestamp)}</TableCell>
              <TableCell className="text-center tabular-nums text-slate-400">{scan.attachmentCount}</TableCell>
              <TableCell className="text-center tabular-nums text-slate-400">{scan.extractedUrlCount}</TableCell>
              <TableCell onClick={stopRowClick} onKeyDown={(event) => event.stopPropagation()} className="text-right">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button type="button" variant="ghost" size="icon" onClick={() => onDelete(scan.id)} aria-label={`Delete ${scan.subject}`} className="text-slate-500 hover:bg-rose-500/10 hover:text-rose-300"><Trash2 aria-hidden="true" /></Button>
                  </TooltipTrigger>
                  <TooltipContent className="border-slate-700 bg-slate-950 text-slate-200">Delete scan</TooltipContent>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TooltipProvider>
  );
}
