import { StatsCard } from '@/components/dashboard/stats-card';
import { RecentScans } from '@/components/dashboard/recent-scans';
import { ThreatOverview } from '@/components/dashboard/threat-overview';
import { MOCK_DASHBOARD_STATS, MOCK_RECENT_SCANS } from '@/lib/mock-data';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2 
} from 'lucide-react';

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold tracking-tight text-slate-900">Security Dashboard</h1>
        <p className="text-slate-500">Real-time overview of your email security posture and threat landscape.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard 
          title="Total Scans" 
          value={MOCK_DASHBOARD_STATS.totalScans} 
          icon={<ShieldCheck size={20} />} 
          trend="+12%" 
          trendUp={true}
        />
        <StatsCard 
          title="Phishing Detected" 
          value={MOCK_DASHBOARD_STATS.phishingDetected} 
          icon={<ShieldAlert size={20} />} 
          trend="+5%" 
          trendUp={false}
          className="border-red-100 bg-red-50/30"
        />
        <StatsCard 
          title="Suspicious Emails" 
          value={MOCK_DASHBOARD_STATS.suspiciousEmails} 
          icon={<AlertTriangle size={20} />} 
          trend="-2%" 
          trendUp={true}
          className="border-amber-100 bg-amber-50/30"
        />
        <StatsCard 
          title="Safe Emails" 
          value={MOCK_DASHBOARD_STATS.safeEmails} 
          icon={<CheckCircle2 size={20} />} 
          trend="+8%" 
          trendUp={true}
          className="border-green-100 bg-green-50/30"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-7">
        <div className="lg:col-span-4">
          <RecentScans scans={MOCK_RECENT_SCANS} />
        </div>
        <div className="lg:col-span-3">
          <ThreatOverview />
        </div>
      </div>
    </div>
  );
}