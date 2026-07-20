import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { ThreatClassification } from '@/types/analysis';

const classificationStyles: Record<ThreatClassification, string> = {
  phishing: 'border-danger/30 bg-danger/10 text-danger',
  suspicious: 'border-warning/30 bg-warning/10 text-warning',
  safe: 'border-success/30 bg-success/10 text-success',
};

export function ClassificationBadge({ classification, className }: { classification: ThreatClassification; className?: string }) {
  return <Badge variant="outline" className={cn('capitalize', classificationStyles[classification], className)}>{classification}</Badge>;
}
