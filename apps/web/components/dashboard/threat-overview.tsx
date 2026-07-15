import { Activity } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import type { ThreatVector } from '@/types';

interface ThreatOverviewProps {
  vectors: ThreatVector[];
}

const severityStyles = {
  high: { bar: 'bg-rose-500', dot: 'bg-rose-400' },
  medium: { bar: 'bg-amber-500', dot: 'bg-amber-400' },
  low: { bar: 'bg-sky-500', dot: 'bg-sky-400' },
};

export function ThreatOverview({ vectors }: ThreatOverviewProps) {
  const maximum = Math.max(...vectors.map((vector) => vector.count), 0);
  const total = vectors.reduce((sum, vector) => sum + vector.count, 0);
  const visibleVectors = vectors.slice(0, 5);

  return (
    <Card className="h-full border-slate-800 bg-slate-900/80">
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base text-slate-100">Threat overview</CardTitle>
            <CardDescription className="mt-1 text-slate-400">Signals observed across saved email analyses.</CardDescription>
          </div>
          <Badge variant="outline" className="border-slate-700 bg-slate-950/50 text-slate-400">All saved scans</Badge>
        </div>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <div className="flex min-h-52 flex-col items-center justify-center text-center">
            <Activity className="h-8 w-8 text-slate-600" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-slate-200">No threat signals</p>
            <p className="mt-1 text-xs text-slate-500">Signal distribution will appear after flagged scans.</p>
          </div>
        ) : (
          <div className="space-y-4" role="img" aria-label={`Threat signal distribution totaling ${total} observations`}>
            {visibleVectors.map((vector) => (
              <div key={vector.label}>
                <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-slate-300">{vector.label}</span>
                  <span className="tabular-nums text-slate-500">{vector.count}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={cn('h-full rounded-full', severityStyles[vector.severity].bar)}
                    style={{ width: `${(vector.count / maximum) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}

        {total > 0 && (
          <>
            <Separator className="my-5 bg-slate-800" />
            <div className="flex flex-wrap gap-x-4 gap-y-2" aria-label="Threat severity legend">
              {(['high', 'medium', 'low'] as const).map((severity) => (
                <div key={severity} className="flex items-center gap-2 text-xs capitalize text-slate-400">
                  <span className={cn('h-2 w-2 rounded-full', severityStyles[severity].dot)} aria-hidden="true" />
                  {severity} severity
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs leading-5 text-slate-500">
              {vectors[0].label} is the leading signal, representing {Math.round((vectors[0].count / total) * 100)}% of observations.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
