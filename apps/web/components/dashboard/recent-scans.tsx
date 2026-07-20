import { ArrowUpRight, Inbox } from 'lucide-react';
import Link from 'next/link';

import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface RecentScansProps {
  scans: ScanRecord[];
  onOpen: (id: string) => void;
  isLoaded: boolean;
}

function formatDate(timestamp: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(timestamp));
}

const riskStyles = {
  safe: 'text-success',
  suspicious: 'text-warning',
  phishing: 'text-danger',
};

export function RecentScans({ scans, onOpen, isLoaded }: RecentScansProps) {
  return (
    <Card className="h-full border-border bg-surface/80">
      <CardHeader className="pb-3">
        <h2 className="text-base font-semibold text-foreground">Recent scans</h2>
        <CardDescription className="text-muted-foreground">The latest email classifications saved in this browser.</CardDescription>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        {!isLoaded ? (
          <div className="space-y-3 px-5 py-5" aria-busy="true" aria-label="Loading recent scans">
            {Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-16 w-full bg-surface-muted" />)}
          </div>
        ) : scans.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
            <Inbox className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-foreground">No scans yet</p>
            <p className="mt-1 max-w-xs text-xs leading-5 text-foreground0">Run an email analysis to create the first locally stored scan.</p>
            <Button asChild size="sm" className="mt-5 bg-primary text-primary-foreground hover:bg-primary">
              <Link href="/analyze">Analyze email</Link>
            </Button>
          </div>
        ) : (
          <>
            <div className="divide-y divide-border md:hidden">
              {scans.map((scan) => (
                <button key={scan.id} type="button" onClick={() => onOpen(scan.id)} className="group block w-full px-5 py-4 text-left transition-colors hover:bg-surface-muted/50 focus-visible:bg-surface-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring" aria-label={`Open scan details for ${scan.subject}`}>
                  <span className="flex items-start justify-between gap-4">
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-semibold text-foreground">{scan.subject}</span>
                      <span className="mt-1 block truncate text-xs text-foreground0">{scan.sender}</span>
                    </span>
                    <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-colors group-hover:text-primary" aria-hidden="true" />
                  </span>
                  <span className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
                    <ClassificationBadge classification={scan.classification} />
                    <span className={cn('text-xs font-semibold tabular-nums', riskStyles[scan.classification])}>Risk {scan.riskScore}/100</span>
                    <span className="text-xs text-foreground0">{formatDate(scan.timestamp)}</span>
                  </span>
                </button>
              ))}
            </div>

            <div className="hidden overflow-x-auto md:block">
              <Table>
                <TableHeader className="bg-background/40">
                  <TableRow className="border-border hover:bg-transparent">
                    <TableHead className="min-w-56 text-muted-foreground">Subject</TableHead>
                    <TableHead className="min-w-48 text-muted-foreground">Sender</TableHead>
                    <TableHead className="text-muted-foreground">Verdict</TableHead>
                    <TableHead className="whitespace-nowrap text-muted-foreground">Risk</TableHead>
                    <TableHead className="whitespace-nowrap text-muted-foreground">Scanned</TableHead>
                    <TableHead className="w-10"><span className="sr-only">Open details</span></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => (
                    <TableRow key={scan.id} role="button" tabIndex={0} onClick={() => onOpen(scan.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(scan.id); } }} aria-label={`Open scan details for ${scan.subject}`} className="group cursor-pointer border-border transition-colors hover:bg-surface-muted/50 focus-visible:bg-surface-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                      <TableCell><p className="max-w-64 truncate font-medium text-foreground" title={scan.subject}>{scan.subject}</p></TableCell>
                      <TableCell><p className="max-w-52 truncate text-muted-foreground" title={scan.sender}>{scan.sender}</p></TableCell>
                      <TableCell><ClassificationBadge classification={scan.classification} /></TableCell>
                      <TableCell className={cn('font-semibold tabular-nums', riskStyles[scan.classification])}>{scan.riskScore}/100</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{formatDate(scan.timestamp)}</TableCell>
                      <TableCell><ArrowUpRight className="h-4 w-4 text-muted-foreground transition-colors group-hover:text-primary" aria-hidden="true" /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
