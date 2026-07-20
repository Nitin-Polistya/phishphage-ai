'use client';

import { AlertTriangle, ScanSearch, ShieldCheck } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import type { DashboardStats, ScanRecord, ThreatVector } from '@/types';

interface SecurityInsightsProps {
  scans: ScanRecord[];
  stats: DashboardStats;
  vectors: ThreatVector[];
  isLoaded: boolean;
}

export function SecurityInsights({ scans, stats, vectors, isLoaded }: SecurityInsightsProps) {
  const highestRisk = scans.reduce<ScanRecord | null>((highest, scan) => (
    !highest || scan.riskScore > highest.riskScore ? scan : highest
  ), null);
  const safeRate = stats.totalScans ? Math.round((stats.safeEmails / stats.totalScans) * 100) : 0;

  return (
    <Card className="border-border bg-surface/80">
      <CardHeader className="pb-4">
        <h2 className="text-base font-semibold text-foreground">Security insights</h2>
      </CardHeader>
      <CardContent>
        {!isLoaded ? (
          <div className="grid gap-5 md:grid-cols-3" aria-busy="true" aria-label="Loading security insights">
            {Array.from({ length: 3 }, (_, index) => <Skeleton key={index} className="h-24 w-full bg-surface-muted" />)}
          </div>
        ) : <div className="grid gap-5 md:grid-cols-3">
          <div className="flex gap-3">
            <ScanSearch className="mt-0.5 h-5 w-5 text-primary" aria-hidden="true" />
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-foreground0">Most common signal</p>
              <p className="mt-1 text-sm font-medium text-foreground">{vectors[0]?.label ?? 'No signals detected'}</p>
              {vectors[0] && <Badge variant="outline" className="mt-2 border-input text-muted-foreground">{vectors[0].count} observations</Badge>}
            </div>
          </div>

          <div className="flex gap-3 md:border-l md:border-border md:pl-5">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-warning" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-foreground0">Highest-risk scan</p>
              <p className="mt-1 truncate text-sm font-medium text-foreground">{highestRisk?.subject ?? 'No recent scans'}</p>
              {highestRisk && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="mt-2 cursor-help border-danger/30 bg-danger/10 text-danger">
                        Risk {highestRisk.riskScore}/100
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent className="border-input bg-background text-foreground">Highest risk score across saved scans</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          </div>

          <div className="flex gap-3 md:border-l md:border-border md:pl-5">
            <ShieldCheck className="mt-0.5 h-5 w-5 text-success" aria-hidden="true" />
            <div className="w-full">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs font-medium uppercase tracking-wide text-foreground0">Safe classification rate</p>
                <span className="text-sm font-semibold tabular-nums text-success">{stats.totalScans ? `${safeRate}%` : '—'}</span>
              </div>
              <Separator className="my-2 bg-surface-muted" />
              <Progress value={safeRate} aria-label={stats.totalScans ? `${safeRate}% of scans classified safe` : 'No scans available for safe classification rate'} className="h-2 bg-surface-muted [&>div]:bg-success" />
              <p className="mt-2 text-xs text-foreground0">{stats.totalScans ? 'Across all saved scans' : 'No scans analyzed yet'}</p>
            </div>
          </div>
        </div>}
      </CardContent>
    </Card>
  );
}
