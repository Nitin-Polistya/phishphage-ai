'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import { AlertCircle, CheckCircle2, ClipboardPaste, Clock3, Loader2, RotateCcw, Shield, X } from 'lucide-react';

import { ApiError, analyzeProductionEmail } from '@/lib/api';
import { EXAMPLE_EMAIL } from '@/lib/example-email';
import type { PredictionResponse } from '@/types/inference';
import { BackendStatus } from './backend-status';
import { RiskScoreCard } from './risk-score-card';

const MAX_EMAIL_BYTES = 2_000_000;
const stages = ['Validating email', 'Parsing headers and content', 'Extracting security indicators', 'Running ML inference', 'Preparing explanation'];

function errorTitle(kind: ApiError['kind']) {
  if (kind === 'backend_unavailable' || kind === 'timeout') return 'Analysis service unavailable';
  if (kind === 'cancelled') return 'Analysis cancelled';
  if (kind === 'validation') return 'Check the email input';
  if (kind === 'service_unavailable') return 'Inference model unavailable';
  return 'Analysis failed';
}

function SignalGroup({ title, values, tone = 'slate' }: { title: string; values: string[]; tone?: 'slate' | 'amber' | 'rose' | 'blue' }) {
  const toneClass = { slate: 'text-slate-400', amber: 'text-amber-300', rose: 'text-rose-300', blue: 'text-blue-300' }[tone];
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-950/45 p-4" aria-label={title}>
      <div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold text-slate-200">{title}</h3><span className={`text-xs ${toneClass}`}>{values.length ? `${values.length} detected` : 'Not available'}</span></div>
      {values.length ? <ul className="mt-3 flex flex-wrap gap-2">{values.map((value) => <li key={`${title}-${value}`} className="rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300">{value.replaceAll('_', ' ')}</li>)}</ul> : <p className="mt-3 text-xs leading-5 text-slate-500">No corresponding indicators were returned by the backend.</p>}
    </section>
  );
}

export function ProductionAnalysis() {
  const [rawEmail, setRawEmail] = useState('');
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);
  useEffect(() => {
    if (!isLoading) return;
    const stageTimer = window.setInterval(() => setStageIndex((current) => (current + 1) % stages.length), 1400);
    const elapsedTimer = window.setInterval(() => setElapsed((current) => current + 0.1), 100);
    return () => { window.clearInterval(stageTimer); window.clearInterval(elapsedTimer); };
  }, [isLoading]);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (isLoading) return;
    if (!rawEmail.trim()) { setError(new ApiError('validation', 'Paste an email before starting analysis.')); return; }
    if (new TextEncoder().encode(rawEmail).length > MAX_EMAIL_BYTES) { setError(new ApiError('validation', 'This email exceeds the 2 MB processing limit.')); return; }
    setError(null); setResult(null); setIsLoading(true); setStageIndex(0); setElapsed(0);
    const controller = new AbortController(); abortRef.current = controller;
    try { setResult(await analyzeProductionEmail(rawEmail, controller.signal)); }
    catch (caught) { setError(caught instanceof ApiError ? caught : new ApiError('unexpected', 'Analysis failed safely. Please try again.')); }
    finally { abortRef.current = null; setIsLoading(false); }
  };

  const clear = () => { abortRef.current?.abort(); abortRef.current = null; setRawEmail(''); setResult(null); setError(null); setIsLoading(false); };

  return (
    <div className="analyze-surface space-y-6">
      <div className="flex flex-col gap-4 border-b border-slate-800 pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-400">Production inference workspace</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Analyze an email</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Paste the full raw email, including headers when available. Content is processed in memory and is not stored by this application.</p></div>
        <BackendStatus />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <form onSubmit={handleSubmit} className="rounded-xl border border-slate-800 bg-slate-900/75 p-5 shadow-xl shadow-black/10 sm:p-6">
          <div className="flex items-center justify-between gap-3"><label htmlFor="production-raw-email" className="text-sm font-semibold text-slate-200">Raw email source</label><span className="text-xs text-slate-500">Headers improve accuracy</span></div>
          <textarea id="production-raw-email" value={rawEmail} onChange={(event) => { setRawEmail(event.target.value); setError(null); }} disabled={isLoading} aria-describedby="raw-email-help raw-email-count" placeholder={'From: sender@example.com\nSubject: Message subject\n\nPaste the message body here...'} className="mt-3 min-h-[380px] w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-200 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 disabled:cursor-not-allowed disabled:opacity-70" />
          <div className="mt-2 flex justify-between gap-3 text-xs text-slate-500"><span id="raw-email-help">Never rendered, fetched, or persisted by this interface.</span><span id="raw-email-count" className="shrink-0 tabular-nums">{rawEmail.length.toLocaleString()} chars</span></div>
          <div className="mt-5 flex flex-wrap gap-2"><button type="button" onClick={() => { setRawEmail(EXAMPLE_EMAIL); setError(null); }} disabled={isLoading} className="inline-flex min-h-10 items-center gap-2 rounded-md border border-slate-700 px-3 text-sm text-slate-300 transition hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-50"><ClipboardPaste className="h-4 w-4" aria-hidden="true" />Use safe example</button><button type="button" onClick={clear} disabled={isLoading && !rawEmail} className="inline-flex min-h-10 items-center gap-2 rounded-md border border-slate-700 px-3 text-sm text-slate-400 transition hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-50"><RotateCcw className="h-4 w-4" aria-hidden="true" />Clear</button></div>
          <div className="mt-5 flex flex-col gap-3 sm:flex-row"><button type="submit" disabled={isLoading || !rawEmail.trim()} className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-md bg-blue-600 px-4 text-sm font-semibold text-white transition hover:bg-blue-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 disabled:cursor-not-allowed disabled:opacity-50">{isLoading ? <><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />Analyzing</> : <><Shield className="h-4 w-4" aria-hidden="true" />Analyze email</>}</button>{isLoading && <button type="button" onClick={() => abortRef.current?.abort()} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-md border border-rose-500/40 px-4 text-sm font-semibold text-rose-300 transition hover:bg-rose-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"><X className="h-4 w-4" aria-hidden="true" />Cancel</button>}</div>
          <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-500"><Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden="true" />Privacy notice: the current submission stays in memory for this analysis and is cleared when you choose Clear or leave the page.</p>
        </form>

        <section aria-live="polite" aria-busy={isLoading}>
          {isLoading && <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-6"><div className="flex items-center gap-3"><Loader2 className="h-5 w-5 animate-spin text-blue-400" aria-hidden="true" /><h2 className="font-semibold text-slate-100">Processing email</h2><span className="ml-auto text-xs tabular-nums text-slate-500">{elapsed.toFixed(1)}s</span></div><p className="mt-4 text-sm text-slate-400">{stages[stageIndex]}…</p><div className="mt-4 h-1 overflow-hidden rounded bg-slate-800"><div className="h-full w-1/3 animate-[pulse_1.4s_ease-in-out_infinite] rounded bg-blue-400" /></div><p className="mt-4 text-xs text-slate-500">This is an indeterminate processing state; the backend does not report staged progress.</p></div>}
          {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-5"><div className="flex gap-3"><AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" aria-hidden="true" /><div><h2 className="font-semibold text-rose-200">{errorTitle(error.kind)}</h2><p className="mt-1 text-sm leading-6 text-slate-300">{error.message}</p>{error.kind !== 'cancelled' && <button type="button" onClick={() => setError(null)} className="mt-3 text-xs font-semibold text-rose-300 underline underline-offset-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400">Dismiss</button>}</div></div></div>}
          {!isLoading && !error && !result && <div className="flex min-h-[420px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center"><CheckCircle2 className="h-10 w-10 text-slate-700" aria-hidden="true" /><h2 className="mt-4 text-lg font-semibold text-slate-300">Your result will appear here</h2><p className="mt-2 max-w-sm text-sm leading-6 text-slate-500">Submit a raw email to receive a calibrated risk score, signal families, and practical recommendations.</p></div>}
          {result && !isLoading && <div className="space-y-4"><RiskScoreCard result={result} /><div className="grid gap-4 sm:grid-cols-3"><div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Phishing probability</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{(result.probability * 100).toFixed(1)}%</p></div><div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Confidence</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{(result.confidence * 100).toFixed(1)}%</p></div><div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Processing time</p><p className="mt-2 flex items-center gap-2 text-2xl font-semibold tabular-nums text-slate-100"><Clock3 className="h-5 w-5 text-blue-400" aria-hidden="true" />{result.processing_time_ms.toFixed(1)}<span className="text-sm text-slate-500">ms</span></p></div></div><div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5"><div className="flex items-center justify-between gap-3"><h2 className="font-semibold text-slate-100">Relevant signal families</h2><span className="text-xs text-slate-500">Model v{result.model_version}</span></div><div className="mt-3 flex flex-wrap gap-2">{result.feature_families.length ? result.feature_families.map((family) => <span key={family} className="rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs text-blue-200">{family.replaceAll('_', ' ')}</span>) : <span className="text-sm text-slate-500">No signal families returned.</span>}</div></div><div className="grid gap-4 md:grid-cols-2"><SignalGroup title="Phishing signals" values={result.signals.phishing_signals} tone="rose" /><SignalGroup title="Urgency indicators" values={result.signals.urgency_indicators} tone="amber" /><SignalGroup title="Authentication" values={result.signals.authentication_signals} tone="blue" /><SignalGroup title="URL indicators" values={result.signals.url_indicators} tone="amber" /></div><div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5"><h2 className="font-semibold text-slate-100">Recommendations</h2><ul className="mt-3 space-y-3">{result.recommendations.map((recommendation) => <li key={recommendation} className="flex gap-3 text-sm leading-6 text-slate-300"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-blue-400" aria-hidden="true" />{recommendation}</li>)}</ul><p className="mt-5 border-t border-slate-800 pt-4 text-xs leading-5 text-slate-500">PhishShield AI provides automated risk analysis and should support—not replace—human judgment and organizational security controls.</p></div></div>}
        </section>
      </div>
    </div>
  );
}
