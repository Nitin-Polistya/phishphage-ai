import { ReactNode } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface StatsCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  supportingText: string;
  tone?: 'neutral' | 'safe' | 'warning' | 'danger';
  className?: string;
}

const toneStyles = {
  neutral: 'border-slate-200 bg-slate-950 text-slate-200',
  safe: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300',
  warning: 'border-amber-500/20 bg-amber-500/10 text-amber-300',
  danger: 'border-rose-500/20 bg-rose-500/10 text-rose-300',
};

export function StatsCard({ title, value, icon, supportingText, tone = 'neutral', className }: StatsCardProps) {
  return (
    <Card className={cn('border-slate-800 bg-slate-900/80 shadow-sm', className)}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-slate-400">{title}</p>
            <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-50">{value}</p>
          </div>
          <div className={cn('rounded-lg border p-2.5', toneStyles[tone])} aria-hidden="true">
            {icon}
          </div>
        </div>
        <Badge variant="outline" className="mt-4 border-slate-700 bg-slate-950/60 font-normal text-slate-400">
          {supportingText}
        </Badge>
      </CardContent>
    </Card>
  );
}
