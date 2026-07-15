import type { Metadata } from 'next';
import Link from 'next/link';
import { AlertTriangle, ArrowRight, Gauge, MailCheck, ScanLine, ShieldAlert } from 'lucide-react';

import { RecentScans } from '@/components/dashboard/recent-scans';
import { SecurityInsights } from '@/components/dashboard/security-insights';
import { StatsCard } from '@/components/dashboard/stats-card';
import { ThreatOverview } from '@/components/dashboard/threat-overview';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { MOCK_DASHBOARD_STATS, MOCK_RECENT_SCANS, MOCK_THREAT_VECTORS } from '@/lib/mock-data';

export const metadata: Metadata = {
  title: 'Dashboard',
};

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-slate-700 bg-slate-900 text-slate-400">
              <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              Demo data · System status: Operational
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
        <StatsCard title="Total Scans" value={MOCK_DASHBOARD_STATS.totalScans.toLocaleString()} supportingText="12% above last period" icon={<ScanLine />} />
        <StatsCard title="Safe Emails" value={MOCK_DASHBOARD_STATS.safeEmails.toLocaleString()} supportingText="82% of all scans" icon={<MailCheck />} tone="safe" />
        <StatsCard title="Suspicious Emails" value={MOCK_DASHBOARD_STATS.suspiciousEmails.toLocaleString()} supportingText="7% need review" icon={<AlertTriangle />} tone="warning" />
        <StatsCard title="Phishing Detected" value={MOCK_DASHBOARD_STATS.phishingDetected.toLocaleString()} supportingText="11% blocked" icon={<ShieldAlert />} tone="danger" />
        <StatsCard title="Average Risk Score" value={`${MOCK_DASHBOARD_STATS.averageRiskScore}/100`} supportingText="Low overall exposure" icon={<Gauge />} />
      </section>

      <section aria-label="Dashboard insights">
        <SecurityInsights scans={MOCK_RECENT_SCANS} stats={MOCK_DASHBOARD_STATS} vectors={MOCK_THREAT_VECTORS} />
      </section>

      <div className="grid gap-6 xl:grid-cols-5">
        <section className="min-w-0 xl:col-span-3" aria-label="Recent email scans">
          <RecentScans scans={MOCK_RECENT_SCANS} />
        </section>
        <section className="min-w-0 xl:col-span-2" aria-label="Threat signal overview">
          <ThreatOverview vectors={MOCK_THREAT_VECTORS} />
        </section>
      </div>
    </div>
  );
}
