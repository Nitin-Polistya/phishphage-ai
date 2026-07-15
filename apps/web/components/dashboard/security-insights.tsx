'use client';

import { AlertTriangle, ScanSearch, ShieldCheck } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import type { DashboardStats, ScanResult, ThreatVector } from '@/types';

interface SecurityInsightsProps {
  scans: ScanResult[];
  stats: DashboardStats;
  vectors: ThreatVector[];
}

export function SecurityInsights({ scans, stats, vectors }: SecurityInsightsProps) {
  const highestRisk = scans.reduce<ScanResult | null>((highest, scan) => (
    !highest || scan.riskScore > highest.riskScore ? scan : highest
  ), null);
  const safeRate = stats.totalScans ? Math.round((stats.safeEmails / stats.totalScans) * 100) : 0;

  return (
    <Card className="border-slate-800 bg-slate-900/80">
      <CardHeader className="pb-4">
        <CardTitle className="text-base text-slate-100">Security insights</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-5 md:grid-cols-3">
          <div className="flex gap-3">
            <ScanSearch className="mt-0.5 h-5 w-5 text-sky-400" aria-hidden="true" />
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Most common signal</p>
              <p className="mt-1 text-sm font-medium text-slate-200">{vectors[0]?.label ?? 'No signals detected'}</p>
              <Badge variant="outline" className="mt-2 border-slate-700 text-slate-400">{vectors[0]?.count ?? 0} observations</Badge>
            </div>
          </div>

          <div className="flex gap-3 md:border-l md:border-slate-800 md:pl-5">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-400" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Highest-risk scan</p>
              <p className="mt-1 truncate text-sm font-medium text-slate-200">{highestRisk?.subject ?? 'No recent scans'}</p>
              {highestRisk && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="mt-2 cursor-help border-rose-500/30 bg-rose-500/10 text-rose-300">
                        Risk {highestRisk.riskScore}/100
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent className="border-slate-700 bg-slate-950 text-slate-200">Mock risk score from recent activity</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          </div>

          <div className="flex gap-3 md:border-l md:border-slate-800 md:pl-5">
            <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-400" aria-hidden="true" />
            <div className="w-full">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Safe classification rate</p>
                <span className="text-sm font-semibold tabular-nums text-emerald-300">{safeRate}%</span>
              </div>
              <Separator className="my-2 bg-slate-800" />
              <Progress value={safeRate} aria-label={`${safeRate}% of scans classified safe`} className="h-2 bg-slate-800 [&>div]:bg-emerald-500" />
              <p className="mt-2 text-xs text-slate-500">Across all demo scans</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
