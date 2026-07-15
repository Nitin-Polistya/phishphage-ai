'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Database, Download, FileText, Info, Lock, RefreshCw, Settings, Shield, Trash2, WifiOff } from 'lucide-react';

import { ConfirmationDialog } from '@/components/history/confirmation-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { usePreferences } from '@/hooks/use-preferences';
import { useScanRecords } from '@/hooks/use-scan-records';
import { API_BASE_URL, ApiError, fetchHealthStatus, validateApiBaseUrl, type HealthResponse } from '@/lib/api';
import { type AppPreferences } from '@/lib/preferences';
import { downloadReports, requiresLargeBatchConfirmation } from '@/lib/reports';
import { clearScans } from '@/lib/scan-store';
import { cn } from '@/lib/utils';

type HealthState =
  | { phase: 'checking'; response: null; message: string; checkedAt: null }
  | { phase: 'online'; response: HealthResponse; message: string; checkedAt: string }
  | { phase: 'offline' | 'invalid' | 'error'; response: null; message: string; checkedAt: string };

type PendingAction = 'clear' | 'export' | null;

const selectClassName = 'h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-300 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20';

function PreferenceToggle({ checked, onCheckedChange, label, description }: { checked: boolean; onCheckedChange: (checked: boolean) => void; label: string; description: string }) {
  return (
    <div className="flex items-start justify-between gap-5 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
      <div><p className="text-sm font-medium text-slate-200">{label}</p><p className="mt-1 text-xs leading-5 text-slate-500">{description}</p></div>
      <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onCheckedChange(!checked)} className={cn('relative mt-0.5 h-6 w-11 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500', checked ? 'bg-blue-600' : 'bg-slate-700')}>
        <span className={cn('absolute left-1 top-1 h-4 w-4 rounded-full bg-white shadow transition-transform', checked ? 'translate-x-5' : 'translate-x-0')} />
      </button>
    </div>
  );
}

function StatusRow({ label, value, description, tone = 'neutral' }: { label: string; value: string; description: string; tone?: 'good' | 'warning' | 'bad' | 'neutral' }) {
  const Icon = tone === 'good' ? CheckCircle2 : tone === 'bad' ? WifiOff : tone === 'warning' ? AlertTriangle : Info;
  return (
    <div className="grid gap-2 border-b border-slate-800 py-4 last:border-0 sm:grid-cols-[180px_1fr]">
      <p className="text-sm font-medium text-slate-300">{label}</p>
      <div><p className={cn('flex items-center gap-2 text-sm font-semibold', tone === 'good' ? 'text-emerald-300' : tone === 'warning' ? 'text-amber-300' : tone === 'bad' ? 'text-rose-300' : 'text-slate-300')}><Icon className="h-4 w-4" aria-hidden="true" />{value}</p><p className="mt-1 text-xs leading-5 text-slate-500">{description}</p></div>
    </div>
  );
}

function formatCheckedAt(timestamp: string | null) {
  if (!timestamp) return 'Not checked yet';
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(timestamp));
}

export function SettingsWorkspace({ frontendVersion }: { frontendVersion: string }) {
  const { preferences, storageAvailable, recoveredFromMalformedData, isLoaded: preferencesLoaded, updatePreferences } = usePreferences();
  const { scans, isLoaded: scansLoaded } = useScanRecords();
  const [health, setHealth] = useState<HealthState>({ phase: 'checking', response: null, message: 'Checking backend availability…', checkedAt: null });
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    if (!validateApiBaseUrl()) {
      setHealth({ phase: 'invalid', response: null, message: 'The configured backend API URL is not a valid HTTP or HTTPS URL.', checkedAt: new Date().toISOString() });
      return;
    }
    setHealth({ phase: 'checking', response: null, message: 'Checking backend availability…', checkedAt: null });
    try {
      const response = await fetchHealthStatus();
      setHealth({ phase: 'online', response, message: `Health endpoint responded with status “${response.status}”.`, checkedAt: new Date().toISOString() });
    } catch (error) {
      const invalid = error instanceof ApiError && error.kind === 'validation';
      setHealth({
        phase: invalid ? 'invalid' : error instanceof ApiError && error.kind === 'backend_unavailable' ? 'offline' : 'error',
        response: null,
        message: error instanceof Error ? error.message : 'The backend health check failed.',
        checkedAt: new Date().toISOString(),
      });
    }
  }, []);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  const latestRuleEngine = useMemo(() => scans.find((scan) => scan.details?.ruleEngine)?.details?.ruleEngine, [scans]);
  const latestMlEngine = useMemo(() => scans.find((scan) => scan.details?.mlEngine)?.details?.mlEngine, [scans]);

  const update = <Key extends keyof AppPreferences,>(key: Key, value: AppPreferences[Key]) => {
    updatePreferences({ [key]: value });
    setNotice('Preference updated.');
  };

  const executeClear = () => {
    const cleared = clearScans();
    setNotice(cleared ? 'Local scan history cleared.' : 'Scan history could not be cleared because browser storage is unavailable.');
    setPendingAction(null);
  };

  const requestClear = () => {
    if (preferences.confirmBeforeClearingHistory) setPendingAction('clear');
    else executeClear();
  };

  const executeExport = () => {
    const downloaded = downloadReports(scans, 'json');
    setNotice(downloaded ? `Exported ${scans.length} scan${scans.length === 1 ? '' : 's'} as privacy-safe JSON.` : 'The scan export could not be started.');
    setPendingAction(null);
  };

  const requestExport = () => {
    if (requiresLargeBatchConfirmation(scans.length)) setPendingAction('export');
    else executeExport();
  };

  const healthTone = health.phase === 'online' ? 'good' : health.phase === 'checking' ? 'neutral' : 'bad';
  const healthValue = health.phase === 'online' ? 'Available' : health.phase === 'checking' ? 'Checking…' : health.phase === 'invalid' ? 'Invalid API URL' : health.phase === 'offline' ? 'Offline' : 'Health check error';

  return (
    <div className="space-y-6">
      <header>
        <Badge variant="outline" className="mb-3 border-slate-700 bg-slate-900 text-slate-400"><Settings className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />Local MVP configuration</Badge>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">Settings &amp; System Status</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Configure this browser’s analysis workspace, manage local data, and inspect live backend availability.</p>
      </header>

      {(!storageAvailable || recoveredFromMalformedData || notice) && (
        <div role="status" aria-live="polite" className={cn('rounded-lg border px-4 py-3 text-sm', !storageAvailable ? 'border-rose-500/30 bg-rose-500/10 text-rose-200' : recoveredFromMalformedData ? 'border-amber-500/30 bg-amber-500/10 text-amber-200' : 'border-blue-500/30 bg-blue-500/10 text-blue-200')}>
          {!storageAvailable ? 'Browser storage is unavailable. Safe defaults remain active, but preference changes and scan data cannot be persisted.' : recoveredFromMalformedData ? 'Malformed saved preferences were ignored and safe defaults were restored.' : notice}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-2">
        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader><CardTitle className="text-base text-slate-100">General preferences</CardTitle><CardDescription className="text-slate-400">Applied across the analysis and history workflows.</CardDescription></CardHeader>
          <CardContent className="space-y-4">
            <label className="block space-y-2"><span className="text-sm font-medium text-slate-300">Default analysis mode</span><select disabled={!preferencesLoaded} value={preferences.defaultAnalysisMode} onChange={(event) => update('defaultAnalysisMode', event.target.value as AppPreferences['defaultAnalysisMode'])} className={selectClassName}><option value="quick_paste">Quick Paste</option><option value="raw_email">Raw Email</option><option value="eml_upload">.eml Upload</option></select></label>
            <PreferenceToggle checked={preferences.saveSuccessfulScans} onCheckedChange={(value) => update('saveSuccessfulScans', value)} label="Save successful scans locally" description="When disabled, analysis results remain visible for the current page session but are not added to dashboard, history, or reports." />
            <PreferenceToggle checked={preferences.confirmBeforeClearingHistory} onCheckedChange={(value) => update('confirmBeforeClearingHistory', value)} label="Confirm before clearing history" description="Controls confirmation for whole-history deletion actions. Individual scan deletion behavior is unchanged." />
            <label className="block space-y-2"><span className="text-sm font-medium text-slate-300">Default history sort order</span><select disabled={!preferencesLoaded} value={preferences.defaultHistorySortOrder} onChange={(event) => update('defaultHistorySortOrder', event.target.value as AppPreferences['defaultHistorySortOrder'])} className={selectClassName}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="highest-risk">Highest risk</option><option value="lowest-risk">Lowest risk</option></select></label>
            <label className="block space-y-2"><span className="text-sm font-medium text-slate-300">Theme preference</span><select disabled={!preferencesLoaded} value={preferences.theme} onChange={(event) => update('theme', event.target.value as AppPreferences['theme'])} className={selectClassName}><option value="system">System</option><option value="dark">Dark</option><option value="light">Light</option></select></label>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Database className="h-4 w-4 text-blue-400" aria-hidden="true" />Privacy and local data</CardTitle><CardDescription className="text-slate-400">Data controls for this browser profile only.</CardDescription></CardHeader>
          <CardContent className="space-y-5">
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Stored scan records</p><p className="mt-2 text-3xl font-semibold tabular-nums text-slate-100">{scansLoaded ? scans.length : '—'}</p></div>
            <div className="space-y-2 text-sm leading-6 text-slate-400"><p className="flex gap-2"><Lock className="mt-1 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />Raw email bodies and complete raw headers are not written to scan storage or included in exports.</p><p className="flex gap-2"><Info className="mt-1 h-4 w-4 shrink-0 text-blue-400" aria-hidden="true" />Settings and scan history are browser/profile specific and do not synchronize between devices.</p></div>
            <div className="flex flex-wrap gap-3"><Button type="button" variant="outline" disabled={!scansLoaded || scans.length === 0} onClick={requestExport} className="border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800 hover:text-white"><Download aria-hidden="true" />Export all scans as JSON</Button><Button type="button" variant="outline" disabled={!scansLoaded || scans.length === 0} onClick={requestClear} className="border-slate-700 bg-slate-950 text-slate-300 hover:bg-rose-500/10 hover:text-rose-300"><Trash2 aria-hidden="true" />Clear local history</Button></div>
          </CardContent>
        </Card>
      </div>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="flex-row items-start justify-between gap-4"><div><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Activity className="h-4 w-4 text-blue-400" aria-hidden="true" />System status</CardTitle><CardDescription className="mt-1 text-slate-400">Live API status plus engine state observed from locally saved analyses.</CardDescription></div><Button type="button" variant="outline" size="sm" disabled={health.phase === 'checking'} onClick={() => void refreshStatus()} className="border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800 hover:text-white"><RefreshCw className={cn(health.phase === 'checking' && 'animate-spin')} aria-hidden="true" />Refresh status</Button></CardHeader>
        <CardContent>
          <StatusRow label="Backend API URL" value={API_BASE_URL} description="Configured with NEXT_PUBLIC_API_BASE_URL; defaults to the local FastAPI service." />
          <StatusRow label="Backend availability" value={healthValue} description={`${health.message} Last check: ${formatCheckedAt(health.checkedAt)}.`} tone={healthTone} />
          <StatusRow label="Rule engine" value={latestRuleEngine ? `Active · ${latestRuleEngine.version}` : 'Not yet observed'} description={latestRuleEngine ? 'Reported by the most recent locally stored scan containing rule-engine metadata.' : 'The health endpoint does not expose rule diagnostics. Run and save an analysis to observe its engine version.'} tone={latestRuleEngine ? 'good' : 'neutral'} />
          <StatusRow label="ML engine" value={latestMlEngine ? `${latestMlEngine.status === 'available' ? 'Available' : 'Unavailable'}${latestMlEngine.version ? ` · ${latestMlEngine.version}` : ''}` : 'Not yet observed'} description={latestMlEngine?.status === 'unavailable' ? 'Optional ML was unavailable for the latest observed scan. Deterministic rule analysis remains functional.' : latestMlEngine?.status === 'available' ? 'Optional ML was available for the latest locally observed analysis.' : 'The health endpoint does not expose ML status. Its state will be recorded after a saved analysis.'} tone={latestMlEngine?.status === 'available' ? 'good' : latestMlEngine?.status === 'unavailable' ? 'warning' : 'neutral'} />
          <StatusRow label="Firebase" value={health.phase === 'online' ? health.response.firebase.replaceAll('_', ' ') : 'Not available'} description={health.phase === 'online' ? 'Informational backend configuration status only. Firebase is not required or used by this local MVP workspace.' : 'Firebase configuration cannot be read while the backend health endpoint is unavailable.'} tone="neutral" />
          <StatusRow label="Frontend version" value={frontendVersion} description="Version reported by the web application package." />
        </CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Shield className="h-4 w-4 text-blue-400" aria-hidden="true" />About PhishPhage AI</CardTitle></CardHeader>
        <CardContent className="grid gap-6 lg:grid-cols-2"><div><p className="text-sm leading-6 text-slate-300">A local-first phishing investigation console that parses email metadata and explains deterministic risk signals, with optional ML assistance when available.</p><p className="mt-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Technology stack</p><p className="mt-2 text-sm text-slate-400">Next.js, React, TypeScript, Tailwind CSS, shadcn/ui, FastAPI, Python, and optional ML services.</p><a href="https://github.com/Nitin-Polistya/phishphage-ai" target="_blank" rel="noreferrer" className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-blue-400 hover:text-blue-300"><FileText className="h-4 w-4" aria-hidden="true" />GitHub repository</a></div><div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4"><p className="flex items-center gap-2 text-sm font-medium text-slate-200"><AlertTriangle className="h-4 w-4 text-amber-300" aria-hidden="true" />Privacy and safety limitations</p><ul className="mt-3 space-y-2 text-xs leading-5 text-slate-500"><li>PhishPhage AI provides decision support, not a guarantee that an email is safe or malicious.</li><li>URLs are not fetched and attachments are not executed.</li><li>Browser storage can be cleared by the user, browser, or device policy.</li><li>Application version: {frontendVersion}. Backend service: {health.phase === 'online' ? health.response.service : 'not currently reported'}.</li></ul></div></CardContent>
      </Card>

      <ConfirmationDialog open={pendingAction !== null} title={pendingAction === 'clear' ? 'Clear all local scan history?' : `Export ${scans.length} scan reports?`} description={pendingAction === 'clear' ? `This permanently removes all ${scans.length} scan records from this browser profile and immediately updates dashboard, history, and reports.` : 'This large export is generated in browser memory and excludes raw email bodies and complete raw headers.'} confirmLabel={pendingAction === 'clear' ? 'Clear history' : 'Export JSON'} tone={pendingAction === 'clear' ? 'danger' : 'primary'} onCancel={() => setPendingAction(null)} onConfirm={pendingAction === 'clear' ? executeClear : executeExport} />
    </div>
  );
}
