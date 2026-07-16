'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, ChevronDown, Code2, Database, Download, HardDrive, Info, RefreshCw, Settings, Trash2, WifiOff } from 'lucide-react';

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
  | { phase: 'checking'; response: null; message: string }
  | { phase: 'online'; response: HealthResponse; message: string }
  | { phase: 'offline' | 'invalid' | 'error'; response: null; message: string };

type PendingAction = 'clear' | 'export' | null;

const selectClassName = 'h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-300 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20';

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function PreferenceToggle({ checked, onCheckedChange, label, description }: { checked: boolean; onCheckedChange: (checked: boolean) => void; label: string; description: string }) {
  return (
    <div className="flex items-start justify-between gap-5 border-b border-slate-800 py-4 last:border-0">
      <div><p className="text-sm font-medium text-slate-200">{label}</p><p className="mt-1 text-xs leading-5 text-slate-500">{description}</p></div>
      <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onCheckedChange(!checked)} className={cn('relative mt-0.5 h-6 w-11 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500', checked ? 'bg-blue-600' : 'bg-slate-700')}>
        <span className={cn('absolute left-1 top-1 h-4 w-4 rounded-full bg-white shadow transition-transform', checked ? 'translate-x-5' : 'translate-x-0')} />
      </button>
    </div>
  );
}

function DeveloperRow({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: 'good' | 'warning' | 'bad' | 'neutral' }) {
  const Icon = tone === 'good' ? CheckCircle2 : tone === 'bad' ? WifiOff : tone === 'warning' ? AlertTriangle : Info;
  return (
    <div className="grid gap-1 border-b border-slate-800 py-3 last:border-0 sm:grid-cols-[180px_minmax(0,1fr)] sm:gap-4">
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={cn('flex min-w-0 items-start gap-2 break-all text-sm', tone === 'good' ? 'text-emerald-300' : tone === 'warning' ? 'text-amber-300' : tone === 'bad' ? 'text-rose-300' : 'text-slate-300')}><Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />{value}</dd>
    </div>
  );
}

export function SettingsWorkspace({ frontendVersion }: { frontendVersion: string }) {
  const { preferences, storageAvailable, recoveredFromMalformedData, isLoaded: preferencesLoaded, updatePreferences } = usePreferences();
  const { scans, isLoaded: scansLoaded } = useScanRecords();
  const [health, setHealth] = useState<HealthState>({ phase: 'checking', response: null, message: 'Checking backend availability…' });
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    if (!validateApiBaseUrl()) {
      setHealth({ phase: 'invalid', response: null, message: 'Invalid API URL' });
      return;
    }
    setHealth({ phase: 'checking', response: null, message: 'Checking…' });
    try {
      const response = await fetchHealthStatus();
      setHealth({ phase: 'online', response, message: 'Available' });
    } catch (error) {
      const invalid = error instanceof ApiError && error.kind === 'validation';
      setHealth({ phase: invalid ? 'invalid' : error instanceof ApiError && error.kind === 'backend_unavailable' ? 'offline' : 'error', response: null, message: invalid ? 'Invalid API URL' : 'Unavailable' });
    }
  }, []);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  const latestRuleEngine = useMemo(() => scans.find((scan) => scan.details?.ruleEngine)?.details?.ruleEngine, [scans]);
  const latestMlEngine = useMemo(() => scans.find((scan) => scan.details?.mlEngine)?.details?.mlEngine, [scans]);
  const storageUsed = useMemo(() => formatBytes(new Blob([JSON.stringify(scans)]).size), [scans]);

  const update = <Key extends keyof AppPreferences,>(key: Key, value: AppPreferences[Key]) => {
    updatePreferences({ [key]: value });
    setNotice('Preference saved locally.');
  };

  const executeClear = () => {
    const cleared = clearScans();
    setNotice(cleared ? 'Local scan history cleared.' : 'Scan history could not be cleared because browser storage is unavailable.');
    setPendingAction(null);
  };

  const requestClear = () => preferences.confirmBeforeClearingHistory ? setPendingAction('clear') : executeClear();
  const executeExport = () => {
    const downloaded = downloadReports(scans, 'json');
    setNotice(downloaded ? `Exported ${scans.length} scan${scans.length === 1 ? '' : 's'} as JSON.` : 'The scan export could not be started.');
    setPendingAction(null);
  };
  const requestExport = () => requiresLargeBatchConfirmation(scans.length) ? setPendingAction('export') : executeExport();

  const healthTone = health.phase === 'online' ? 'good' : health.phase === 'checking' ? 'neutral' : 'bad';
  const firebaseValue = health.phase === 'online' ? health.response.firebase.replaceAll('_', ' ') : 'Not available';

  return (
    <div className="settings-surface space-y-6">
      <header>
        <Badge variant="outline" className="mb-3 border-slate-700 bg-slate-900 text-slate-400"><Settings className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />Browser workspace</Badge>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">Settings</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Manage analysis defaults, appearance, and data stored in this browser.</p>
      </header>

      {(!storageAvailable || recoveredFromMalformedData || notice) && <div role="status" aria-live="polite" className={cn('rounded-lg border px-4 py-3 text-sm', !storageAvailable ? 'border-rose-500/30 bg-rose-500/10 text-rose-200' : recoveredFromMalformedData ? 'border-amber-500/30 bg-amber-500/10 text-amber-200' : 'border-blue-500/30 bg-blue-500/10 text-blue-200')}>{!storageAvailable ? 'Browser storage is unavailable. Changes cannot be persisted.' : recoveredFromMalformedData ? 'Malformed preferences were ignored and safe defaults restored.' : notice}</div>}

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader><CardTitle className="text-base text-slate-100">Workspace information</CardTitle><CardDescription className="text-slate-400">A concise view of this local browser workspace.</CardDescription></CardHeader>
        <CardContent className="grid gap-px overflow-hidden rounded-lg border border-slate-800 bg-slate-800 sm:grid-cols-3">
          {[
            { label: 'Stored scans', value: scansLoaded ? String(scans.length) : '—', icon: Database },
            { label: 'Storage used', value: scansLoaded ? storageUsed : '—', icon: HardDrive },
            { label: 'Application version', value: frontendVersion, icon: Info },
          ].map((item) => <div key={item.label} className="bg-slate-950/60 p-4"><item.icon className="h-4 w-4 text-slate-500" aria-hidden="true" /><p className="mt-3 text-xs uppercase tracking-wide text-slate-500">{item.label}</p><p className="mt-1 text-lg font-semibold tabular-nums text-slate-100">{item.value}</p></div>)}
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.25fr)_minmax(320px,.75fr)]">
        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader><CardTitle className="text-base text-slate-100">Preferences</CardTitle><CardDescription className="text-slate-400">Changes save immediately to this browser profile.</CardDescription></CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-5 sm:grid-cols-2">
              <label className="block space-y-2"><span className="text-sm font-medium text-slate-300">Theme</span><select disabled={!preferencesLoaded} value={preferences.theme} onChange={(event) => update('theme', event.target.value as AppPreferences['theme'])} className={selectClassName}><option value="system">System</option><option value="dark">Dark</option><option value="light">Light</option></select></label>
              <label className="block space-y-2"><span className="text-sm font-medium text-slate-300">Default analysis mode</span><select disabled={!preferencesLoaded} value={preferences.defaultAnalysisMode} onChange={(event) => update('defaultAnalysisMode', event.target.value as AppPreferences['defaultAnalysisMode'])} className={selectClassName}><option value="quick_paste">Quick Paste</option><option value="raw_email">Raw Email</option><option value="eml_upload">.eml Upload</option></select></label>
              <label className="block space-y-2 sm:col-span-2"><span className="text-sm font-medium text-slate-300">History sorting</span><select disabled={!preferencesLoaded} value={preferences.defaultHistorySortOrder} onChange={(event) => update('defaultHistorySortOrder', event.target.value as AppPreferences['defaultHistorySortOrder'])} className={selectClassName}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="highest-risk">Highest risk</option><option value="lowest-risk">Lowest risk</option></select></label>
            </div>
            <PreferenceToggle checked={preferences.saveSuccessfulScans} onCheckedChange={(value) => update('saveSuccessfulScans', value)} label="Save scans locally" description="Store completed analyses for dashboard, history, and reports in this browser." />
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-900/80">
          <CardHeader><CardTitle className="text-base text-slate-100">Local data</CardTitle><CardDescription className="text-slate-400">Export or clear privacy-safe scan records.</CardDescription></CardHeader>
          <CardContent><p className="text-sm leading-6 text-slate-400">Raw email bodies and full raw headers are excluded from local scan history and exports.</p><div className="mt-5 grid gap-3"><Button type="button" variant="outline" disabled={!scansLoaded || scans.length === 0} onClick={requestExport} className="justify-start border-slate-700 bg-slate-950 text-slate-300 hover:bg-slate-800 hover:text-white"><Download aria-hidden="true" />Export local data</Button><Button type="button" variant="outline" disabled={!scansLoaded || scans.length === 0} onClick={requestClear} className="justify-start border-slate-700 bg-slate-950 text-slate-300 hover:bg-rose-500/10 hover:text-rose-300"><Trash2 aria-hidden="true" />Clear local data</Button></div></CardContent>
        </Card>
      </div>

      <details className="group rounded-lg border border-slate-800 bg-slate-900/50">
        <summary className="flex cursor-pointer list-none items-center gap-3 px-5 py-4 text-sm font-medium text-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"><Code2 className="h-4 w-4 text-slate-500" aria-hidden="true" />Developer Details<span className="ml-auto text-xs font-normal text-slate-500">Optional diagnostics</span><ChevronDown className="h-4 w-4 text-slate-500 transition-transform group-open:rotate-180" aria-hidden="true" /></summary>
        <div className="border-t border-slate-800 px-5 pb-4">
          <div className="flex justify-end py-3"><Button type="button" variant="ghost" size="sm" disabled={health.phase === 'checking'} onClick={() => void refreshStatus()} className="text-slate-400 hover:bg-slate-800 hover:text-slate-200"><RefreshCw className={cn(health.phase === 'checking' && 'animate-spin')} aria-hidden="true" />Refresh</Button></div>
          <dl><DeveloperRow label="API URL" value={API_BASE_URL} /><DeveloperRow label="Backend availability" value={health.message} tone={healthTone} /><DeveloperRow label="Rule engine status" value={latestRuleEngine ? `Active · ${latestRuleEngine.version}` : 'Not yet observed'} tone={latestRuleEngine ? 'good' : 'neutral'} /><DeveloperRow label="ML engine status" value={latestMlEngine ? `${latestMlEngine.status === 'available' ? 'Available' : 'Unavailable'}${latestMlEngine.version ? ` · ${latestMlEngine.version}` : ''}` : 'Not yet observed'} tone={latestMlEngine?.status === 'available' ? 'good' : latestMlEngine?.status === 'unavailable' ? 'warning' : 'neutral'} /><DeveloperRow label="Firebase status" value={firebaseValue} /></dl>
        </div>
      </details>

      <ConfirmationDialog open={pendingAction !== null} title={pendingAction === 'clear' ? 'Clear all local scan history?' : `Export ${scans.length} scan reports?`} description={pendingAction === 'clear' ? `This permanently removes all ${scans.length} scan records from this browser profile.` : 'This large export is generated in browser memory and excludes raw email bodies and complete raw headers.'} confirmLabel={pendingAction === 'clear' ? 'Clear history' : 'Export JSON'} tone={pendingAction === 'clear' ? 'danger' : 'primary'} onCancel={() => setPendingAction(null)} onConfirm={pendingAction === 'clear' ? executeClear : executeExport} />
    </div>
  );
}
