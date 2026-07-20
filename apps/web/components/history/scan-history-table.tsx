'use client';

import { KeyboardEvent, MouseEvent } from 'react';
import { Clock3, Link as LinkIcon, Mail, Paperclip, Trash2 } from 'lucide-react';

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
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
}

function dateGroup(timestamp: string) {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  const key = date.toDateString();
  if (key === today.toDateString()) return 'Today';
  if (key === yesterday.toDateString()) return 'Yesterday';
  return new Intl.DateTimeFormat('en', { dateStyle: 'long' }).format(date);
}

function TruncatedValue({ children }: { children: string }) {
  return <Tooltip><TooltipTrigger asChild><span className="block max-w-64 truncate" tabIndex={0}>{children}</span></TooltipTrigger><TooltipContent className="max-w-sm break-words border-input bg-background text-foreground">{children}</TooltipContent></Tooltip>;
}

export function ScanHistoryTable({ scans, selectedIds, onOpen, onDelete, onToggle, onTogglePage }: ScanHistoryTableProps) {
  const pageIds = scans.map((scan) => scan.id);
  const pageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
  const openFromKeyboard = (event: KeyboardEvent<HTMLTableRowElement>, id: string) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(id); } };
  const stopRowClick = (event: MouseEvent) => event.stopPropagation();

  return (
    <TooltipProvider delayDuration={300}>
      <div className="md:hidden">
        <label className="flex items-center gap-3 border-b border-border bg-background/40 px-4 py-3 text-xs text-muted-foreground"><input type="checkbox" checked={pageSelected} onChange={(event) => onTogglePage(pageIds, event.target.checked)} aria-label="Select all scans on this page" className="h-4 w-4 rounded border-input bg-background accent-blue-600" />Select this page</label>
        <div className="relative px-4 py-2">
          <span className="absolute bottom-4 left-[25px] top-4 w-px bg-surface-muted" aria-hidden="true" />
          {scans.map((scan, index) => {
            const group = dateGroup(scan.timestamp);
            const showGroup = index === 0 || dateGroup(scans[index - 1].timestamp) !== group;
            return <div key={scan.id}>{showGroup && <p className="relative z-10 my-3 ml-8 w-fit bg-surface px-2 text-[10px] font-semibold uppercase tracking-wider text-foreground0">{group}</p>}<article className={cn('relative mb-3 ml-8 rounded-lg border border-border bg-background/45 p-4', selectedIds.has(scan.id) && 'border-primary/40 bg-primary/5')}><span className={cn('absolute -left-[27px] top-5 h-3 w-3 rounded-full border-2 border-border', scan.classification === 'phishing' ? 'bg-danger' : scan.classification === 'suspicious' ? 'bg-warning' : 'bg-success')} aria-hidden="true" /><div className="flex items-start gap-3"><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="mt-1 h-4 w-4 shrink-0 rounded border-input bg-background accent-blue-600" /><button type="button" onClick={() => onOpen(scan.id)} className="min-w-0 flex-1 text-left"><p className="truncate text-sm font-semibold text-foreground">{scan.subject}</p><p className="mt-1 flex items-center gap-1.5 truncate text-xs text-foreground0"><Mail className="h-3 w-3" aria-hidden="true" />{scan.sender}</p></button><Button type="button" variant="ghost" size="icon" onClick={() => onDelete(scan.id)} aria-label={`Delete ${scan.subject}`} className="-mr-2 -mt-2 text-foreground0 hover:bg-danger/10 hover:text-danger"><Trash2 aria-hidden="true" /></Button></div><div className="mt-4 flex flex-wrap items-center gap-2 pl-7"><ClassificationBadge classification={scan.classification} /><span className={cn('text-sm font-semibold tabular-nums', scan.riskScore >= 70 ? 'text-danger' : scan.riskScore >= 30 ? 'text-warning' : 'text-success')}>{scan.riskScore}/100</span><span className="flex items-center gap-1 text-xs text-foreground0"><Clock3 className="h-3 w-3" aria-hidden="true" />{formatDate(scan.timestamp)}</span><span className="ml-auto flex items-center gap-2 text-xs text-foreground0"><span className="flex items-center gap-1"><Paperclip className="h-3 w-3" />{scan.attachmentCount}</span><span className="flex items-center gap-1"><LinkIcon className="h-3 w-3" />{scan.extractedUrlCount}</span></span></div></article></div>;
          })}
        </div>
      </div>

      <div className="hidden overflow-x-auto md:block">
        <Table className="min-w-[980px]"><TableHeader className="bg-background/50"><TableRow className="border-border hover:bg-transparent"><TableHead className="w-12"><input type="checkbox" checked={pageSelected} onChange={(event) => onTogglePage(pageIds, event.target.checked)} aria-label="Select all scans on this page" className="h-4 w-4 rounded border-input bg-background accent-blue-600" /></TableHead><TableHead className="min-w-64 text-muted-foreground">Subject</TableHead><TableHead className="min-w-48 text-muted-foreground">Sender</TableHead><TableHead className="text-muted-foreground">Verdict</TableHead><TableHead className="whitespace-nowrap text-muted-foreground">Risk</TableHead><TableHead className="whitespace-nowrap text-muted-foreground">Confidence</TableHead><TableHead className="min-w-44 whitespace-nowrap text-muted-foreground">Scanned</TableHead><TableHead className="text-center text-muted-foreground">Files</TableHead><TableHead className="text-center text-muted-foreground">URLs</TableHead><TableHead className="w-14"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader>
          <TableBody>{scans.map((scan) => <TableRow key={scan.id} role="button" tabIndex={0} aria-label={`Open scan details for ${scan.subject}`} data-state={selectedIds.has(scan.id) ? 'selected' : undefined} onClick={() => onOpen(scan.id)} onKeyDown={(event) => openFromKeyboard(event, scan.id)} className="cursor-pointer border-border transition-colors hover:bg-surface-muted/50 focus-visible:bg-surface-muted/50 focus-visible:outline-none"><TableCell onClick={stopRowClick} onKeyDown={(event) => event.stopPropagation()}><input type="checkbox" checked={selectedIds.has(scan.id)} onChange={() => onToggle(scan.id)} aria-label={`Select ${scan.subject}`} className="h-4 w-4 rounded border-input bg-background accent-blue-600" /></TableCell><TableCell className="font-medium text-foreground"><TruncatedValue>{scan.subject}</TruncatedValue></TableCell><TableCell className="text-muted-foreground"><TruncatedValue>{scan.sender}</TruncatedValue></TableCell><TableCell><ClassificationBadge classification={scan.classification} /></TableCell><TableCell className={cn('font-semibold tabular-nums', scan.riskScore >= 70 ? 'text-danger' : scan.riskScore >= 30 ? 'text-warning' : 'text-success')}>{scan.riskScore}/100</TableCell><TableCell className="tabular-nums text-muted-foreground">{Math.round(scan.confidence * 100)}%</TableCell><TableCell className="whitespace-nowrap text-muted-foreground">{formatDate(scan.timestamp)}</TableCell><TableCell className="text-center tabular-nums text-muted-foreground">{scan.attachmentCount}</TableCell><TableCell className="text-center tabular-nums text-muted-foreground">{scan.extractedUrlCount}</TableCell><TableCell onClick={stopRowClick} onKeyDown={(event) => event.stopPropagation()} className="text-right"><Tooltip><TooltipTrigger asChild><Button type="button" variant="ghost" size="icon" onClick={() => onDelete(scan.id)} aria-label={`Delete ${scan.subject}`} className="text-foreground0 hover:bg-danger/10 hover:text-danger"><Trash2 aria-hidden="true" /></Button></TooltipTrigger><TooltipContent className="border-input bg-background text-foreground">Delete scan</TooltipContent></Tooltip></TableCell></TableRow>)}</TableBody>
        </Table>
      </div>
    </TooltipProvider>
  );
}
