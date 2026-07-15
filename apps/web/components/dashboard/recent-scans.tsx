import { Eye, Inbox } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface RecentScansProps {
  scans: ScanRecord[];
}

const classificationStyles: Record<ScanRecord['classification'], string> = {
  phishing: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  suspicious: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  safe: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
};

function formatDate(timestamp: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(timestamp));
}

export function RecentScans({ scans }: RecentScansProps) {
  return (
    <Card className="h-full border-slate-800 bg-slate-900/80">
      <CardHeader className="pb-3">
        <CardTitle className="text-base text-slate-100">Recent scans</CardTitle>
        <CardDescription className="text-slate-400">The latest email classifications saved in this browser.</CardDescription>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        {scans.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
            <Inbox className="h-8 w-8 text-slate-600" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-slate-200">No scans yet</p>
            <p className="mt-1 text-xs text-slate-500">Analyzed emails will appear here.</p>
          </div>
        ) : (
          <Table>
            <TableHeader className="bg-slate-950/40">
              <TableRow className="border-slate-800 hover:bg-transparent">
                <TableHead className="min-w-52 text-slate-400">Subject</TableHead>
                <TableHead className="hidden min-w-52 text-slate-400 md:table-cell">Sender</TableHead>
                <TableHead className="text-slate-400">Classification</TableHead>
                <TableHead className="hidden whitespace-nowrap text-slate-400 sm:table-cell">Risk score</TableHead>
                <TableHead className="hidden whitespace-nowrap text-slate-400 lg:table-cell">Date</TableHead>
                <TableHead className="w-20 text-right text-slate-400">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id} className="border-slate-800 hover:bg-slate-800/40">
                  <TableCell>
                    <p className="max-w-64 truncate font-medium text-slate-200">{scan.subject}</p>
                    <p className="mt-1 max-w-64 truncate text-xs text-slate-500 md:hidden">{scan.sender}</p>
                    <p className="mt-1 text-xs text-slate-500 sm:hidden">Risk {scan.riskScore}/100</p>
                  </TableCell>
                  <TableCell className="hidden max-w-56 truncate text-slate-400 md:table-cell">{scan.sender}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn('capitalize', classificationStyles[scan.classification])}>
                      {scan.classification}
                    </Badge>
                  </TableCell>
                  <TableCell className="hidden font-medium tabular-nums text-slate-300 sm:table-cell">
                    {scan.riskScore}/100
                  </TableCell>
                  <TableCell className="hidden whitespace-nowrap text-slate-400 lg:table-cell">{formatDate(scan.timestamp)}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" disabled aria-label={`View ${scan.subject} scan details`} className="text-slate-500">
                      <Eye aria-hidden="true" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
