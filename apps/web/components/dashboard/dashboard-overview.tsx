'use client';

import { useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, FileText, Gauge, History, MailCheck, ScanLine, ShieldAlert } from 'lucide-react';

import { RecentScans } from '@/components/dashboard/recent-scans';
import { SecurityInsights } from '@/components/dashboard/security-insights';
import { StatsCard } from '@/components/dashboard/stats-card';
import { ThreatOverview } from '@/components/dashboard/threat-overview';
import { ScanDetailPanel } from '@/components/history/scan-detail-panel';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useScanRecords } from '@/hooks/use-scan-records';
import { calculateDashboardStats, calculateThreatVectors } from '@/lib/scan-store';

function percentage(part: number, total: number) {
  return total ? Math.round((part / total) * 100) : 0;
}

export function DashboardOverview() {
  const { scans, isLoaded } = useScanRecords();
  const [openScanId, setOpenScanId] = useState<string | null>(null);
  const stats = calculateDashboardStats(scans);
  const vectors = calculateThreatVectors(scans);
  const selectedScan = openScanId ? scans.find((scan) => scan.id === openScanId) ?? null : null;
  const emptySupport = isLoaded ? 'No scans recorded yet' : 'Loading saved scans';

  return (
    <div className="dashboard-surface space-y-8">
      <header className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <Badge variant="outline" className="mb-3 border-input bg-surface text-muted-foreground">
            <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-success" aria-hidden="true" />
            {isLoaded ? 'Local data - stored in this browser' : 'Loading local scan data...'}
          </Badge>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">PhishShield AI Dashboard</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            Monitor recent phishing-detection activity, risk distribution, and the signals driving email classifications.
          </p>
        </div>

        <nav aria-label="Dashboard quick actions" className="grid w-full gap-2 sm:grid-cols-3 lg:w-auto">
          <Button asChild className="bg-primary text-primary-foreground hover:bg-primary">
            <Link href="/analyze"><ScanLine aria-hidden="true" />Analyze email</Link>
          </Button>
          <Button asChild variant="outline" className="border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground">
            <Link href="/history"><History aria-hidden="true" />View history</Link>
          </Button>
          <Button asChild variant="outline" className="border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground">
            <Link href="/reports"><FileText aria-hidden="true" />Open reports</Link>
          </Button>
        </nav>
      </header>

      <section aria-labelledby="dashboard-statistics-heading">
        <div className="mb-3 flex items-end justify-between gap-4">
          <h2 id="dashboard-statistics-heading" className="text-sm font-semibold text-foreground">Scan summary</h2>
          <p className="text-xs text-foreground0">All locally stored scans</p>
        </div>
        <div className="grid gap-px overflow-hidden rounded-xl bg-surface-muted shadow-sm sm:grid-cols-2 xl:grid-cols-5">
          <StatsCard title="Total scans" value={isLoaded ? stats.totalScans.toLocaleString() : '--'} supportingText={stats.totalScans ? 'Saved in this browser' : emptySupport} icon={<ScanLine />} />
          <StatsCard title="Safe" value={isLoaded ? stats.safeEmails.toLocaleString() : '--'} supportingText={stats.totalScans ? `${percentage(stats.safeEmails, stats.totalScans)}% of all scans` : emptySupport} icon={<MailCheck />} tone="safe" />
          <StatsCard title="Suspicious" value={isLoaded ? stats.suspiciousEmails.toLocaleString() : '--'} supportingText={stats.totalScans ? `${percentage(stats.suspiciousEmails, stats.totalScans)}% of all scans` : emptySupport} icon={<AlertTriangle />} tone="warning" />
          <StatsCard title="Phishing" value={isLoaded ? stats.phishingDetected.toLocaleString() : '--'} supportingText={stats.totalScans ? `${percentage(stats.phishingDetected, stats.totalScans)}% of all scans` : emptySupport} icon={<ShieldAlert />} tone="danger" />
          <StatsCard title="Average risk" value={isLoaded && stats.totalScans ? `${stats.averageRiskScore}/100` : '--'} supportingText={stats.totalScans ? 'Across all saved scans' : emptySupport} icon={<Gauge />} className="sm:col-span-2 xl:col-span-1" />
        </div>
      </section>

      <section aria-label="Security insights">
        <SecurityInsights scans={scans} stats={stats} vectors={vectors} isLoaded={isLoaded} />
      </section>

      <div className="grid gap-6 xl:grid-cols-5">
        <section className="min-w-0 xl:col-span-3" aria-label="Recent email scans">
          <RecentScans scans={scans.slice(0, 5)} onOpen={setOpenScanId} isLoaded={isLoaded} />
        </section>
        <section className="min-w-0 xl:col-span-2" aria-label="Threat signal overview">
          <ThreatOverview vectors={vectors} isLoaded={isLoaded} />
        </section>
      </div>

      {selectedScan && <ScanDetailPanel scan={selectedScan} onClose={() => setOpenScanId(null)} />}
    </div>
  );
}
