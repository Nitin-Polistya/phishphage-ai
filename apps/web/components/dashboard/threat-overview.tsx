import { Activity } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import type { ThreatVector } from '@/types';

interface ThreatOverviewProps {
  vectors: ThreatVector[];
  isLoaded: boolean;
}

const severityStyles = {
  high: { bar: 'bg-danger', dot: 'bg-danger' },
  medium: { bar: 'bg-warning', dot: 'bg-warning' },
  low: { bar: 'bg-primary', dot: 'bg-primary' },
};

export function ThreatOverview({ vectors, isLoaded }: ThreatOverviewProps) {
  const maximum = Math.max(...vectors.map((vector) => vector.count), 0);
  const total = vectors.reduce((sum, vector) => sum + vector.count, 0);
  const visibleVectors = vectors.slice(0, 5);

  return (
    <Card className="h-full border-border bg-surface/80">
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">Threat overview</h2>
            <CardDescription className="mt-1 text-muted-foreground">Signals observed across saved email analyses.</CardDescription>
          </div>
          <Badge variant="outline" className="border-input bg-background/50 text-muted-foreground">All saved scans</Badge>
        </div>
      </CardHeader>
      <CardContent>
        {!isLoaded ? (
          <div className="space-y-5 py-2" aria-busy="true" aria-label="Loading threat overview">
            {Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-9 w-full bg-surface-muted" />)}
          </div>
        ) : total === 0 ? (
          <div className="flex min-h-52 flex-col items-center justify-center text-center">
            <Activity className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-foreground">No threat signals</p>
            <p className="mt-1 text-xs text-foreground0">Signal distribution will appear after flagged scans.</p>
          </div>
        ) : (
          <div className="space-y-4" role="img" aria-label={`Threat signal distribution totaling ${total} observations`}>
            {visibleVectors.map((vector) => (
              <div key={vector.label}>
                <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-muted-foreground">{vector.label}</span>
                  <span className="tabular-nums text-foreground0">{vector.count}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-surface-muted">
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
            <Separator className="my-5 bg-surface-muted" />
            <div className="flex flex-wrap gap-x-4 gap-y-2" aria-label="Threat severity legend">
              {(['high', 'medium', 'low'] as const).map((severity) => (
                <div key={severity} className="flex items-center gap-2 text-xs capitalize text-muted-foreground">
                  <span className={cn('h-2 w-2 rounded-full', severityStyles[severity].dot)} aria-hidden="true" />
                  {severity} severity
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs leading-5 text-foreground0">
              {vectors[0].label} is the leading signal, representing {Math.round((vectors[0].count / total) * 100)}% of observations.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
