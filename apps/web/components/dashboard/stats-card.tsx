import { ReactNode } from 'react';
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
  neutral: 'bg-blue-500/10 text-blue-300',
  safe: 'bg-emerald-500/10 text-emerald-300',
  warning: 'bg-amber-500/10 text-amber-300',
  danger: 'bg-rose-500/10 text-rose-300',
};

export function StatsCard({ title, value, icon, supportingText, tone = 'neutral', className }: StatsCardProps) {
  return (
    <article className={cn('flex min-h-36 flex-col justify-between bg-slate-900 p-5 sm:min-h-40 xl:p-6', className)}>
      <div className="flex items-start justify-between gap-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">{title}</p>
        <span className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg [&>svg]:h-4 [&>svg]:w-4', toneStyles[tone])} aria-hidden="true">
          {icon}
        </span>
      </div>
      <div>
        <p className="text-3xl font-semibold tracking-tight text-slate-50 tabular-nums">{value}</p>
        <p className="mt-1.5 text-xs leading-5 text-slate-500">{supportingText}</p>
      </div>
    </article>
  );
}
