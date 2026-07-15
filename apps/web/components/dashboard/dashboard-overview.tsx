'use client';

import Link from 'next/link';
import { AlertTriangle, ArrowRight, Gauge, MailCheck, ScanLine, ShieldAlert } from 'lucide-react';

import { RecentScans } from '@/components/dashboard/recent-scans';
import { SecurityInsights } from '@/components/dashboard/security-insights';
import { StatsCard } from '@/components/dashboard/stats-card';
import { ThreatOverview } from '@/components/dashboard/threat-overview';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useScanRecords } from '@/hooks/use-scan-records';
import { calculateDashboardStats, calculateThreatVectors } from '@/lib/scan-store';

function percentage(part: number, total: number) {
  return total ? Math.round((part / total) * 100) : 0;
}

export function DashboardOverview() {
  const { scans, isLoaded } = useScanRecords();
  const stats = calculateDashboardStats(scans);
  const vectors = calculateThreatVectors(scans);
  const emptySupport = isLoaded ? 'No analyses recorded' : 'Loading saved scans';

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-slate-700 bg-slate-900 text-slate-400">
              <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              {isLoaded ? 'Local data · Stored in this browser' : 'Loading local scan data…'}
            </Badge>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">PhishPhage AI Dashboard</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Monitor recent phishing-detection activity, risk distribution, and the signals driving email classifications.
          </p>
        </div>
        <Button asChild className="w-full bg-blue-600 text-white hover:bg-blue-500 sm:w-auto">
          <Link href="/analyze">
            Analyze an email
            <ArrowRight aria-hidden="true" />
          </Link>
        </Button>
      </header>

      <section aria-label="Email security statistics" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StatsCard title="Total Scans" value={isLoaded ? stats.totalScans.toLocaleString() : '—'} supportingText={stats.totalScans ? 'Saved in this browser' : emptySupport} icon={<ScanLine />} />
        <StatsCard title="Safe Emails" value={isLoaded ? stats.safeEmails.toLocaleString() : '—'} supportingText={stats.totalScans ? `${percentage(stats.safeEmails, stats.totalScans)}% of all scans` : emptySupport} icon={<MailCheck />} tone="safe" />
        <StatsCard title="Suspicious Emails" value={isLoaded ? stats.suspiciousEmails.toLocaleString() : '—'} supportingText={stats.totalScans ? `${percentage(stats.suspiciousEmails, stats.totalScans)}% of all scans` : emptySupport} icon={<AlertTriangle />} tone="warning" />
        <StatsCard title="Phishing Detected" value={isLoaded ? stats.phishingDetected.toLocaleString() : '—'} supportingText={stats.totalScans ? `${percentage(stats.phishingDetected, stats.totalScans)}% of all scans` : emptySupport} icon={<ShieldAlert />} tone="danger" />
        <StatsCard title="Average Risk Score" value={isLoaded && stats.totalScans ? `${stats.averageRiskScore}/100` : '—'} supportingText={stats.totalScans ? 'Across all saved scans' : emptySupport} icon={<Gauge />} />
      </section>

      <section aria-label="Dashboard insights">
        <SecurityInsights scans={scans} stats={stats} vectors={vectors} />
      </section>

      <div className="grid gap-6 xl:grid-cols-5">
        <section className="min-w-0 xl:col-span-3" aria-label="Recent email scans">
          <RecentScans scans={scans.slice(0, 5)} />
        </section>
        <section className="min-w-0 xl:col-span-2" aria-label="Threat signal overview">
          <ThreatOverview vectors={vectors} />
        </section>
      </div>
    </div>
  );
}
