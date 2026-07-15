import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { ThreatClassification } from '@/types/analysis';

const classificationStyles: Record<ThreatClassification, string> = {
  phishing: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  suspicious: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  safe: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
};

export function ClassificationBadge({ classification, className }: { classification: ThreatClassification; className?: string }) {
  return <Badge variant="outline" className={cn('capitalize', classificationStyles[classification], className)}>{classification}</Badge>;
}
