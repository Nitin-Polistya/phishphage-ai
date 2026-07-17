import {
  AlertTriangle, Check, CheckCircle2, Circle, CircleDot, ExternalLink, FileWarning,
  Info, Paperclip, ShieldAlert, Sparkles,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import type { EmailAttachmentMetadata, ThreatClassification, ThreatSeverity, ThreatSignal, UnifiedAnalysisResponse } from '@/types/analysis';

const riskyExtensions = ['.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.iso', '.img', '.zip', '.rar', '.docm', '.xlsm', '.pptm'];
const verdictStyles: Record<ThreatClassification, { text: string; border: string; badge: string; progress: string; meter: string; icon: typeof CheckCircle2 }> = {
  safe: { text: 'text-emerald-300', border: 'border-emerald-500/30', badge: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300', progress: '[&>div]:bg-emerald-500', meter: '#10b981', icon: CheckCircle2 },
  suspicious: { text: 'text-amber-300', border: 'border-amber-500/30', badge: 'border-amber-500/30 bg-amber-500/10 text-amber-300', progress: '[&>div]:bg-amber-500', meter: '#f59e0b', icon: AlertTriangle },
  phishing: { text: 'text-rose-300', border: 'border-rose-500/30', badge: 'border-rose-500/30 bg-rose-500/10 text-rose-300', progress: '[&>div]:bg-rose-500', meter: '#f43f5e', icon: ShieldAlert },
};
const severityStyles: Record<ThreatSeverity, string> = {
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  high: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
};

function extensionOf(filename: string | null) {
  return filename?.toLowerCase().match(/\.[^.]+$/)?.[0] ?? '—';
}

function isRisky(attachment: EmailAttachmentMetadata) {
  return attachment.suspicious_extension ?? riskyExtensions.includes(extensionOf(attachment.filename));
}

function LoadingResults() {
  return <Card className="border-slate-800 bg-slate-900/80" role="status" aria-live="polite" aria-label="Analysis in progress"><CardContent className="p-6 sm:p-8"><div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_300px]"><div className="space-y-4"><Skeleton className="h-4 w-28 bg-slate-800" /><Skeleton className="h-10 w-48 bg-slate-800" /><Skeleton className="h-20 w-full max-w-xl bg-slate-800" /></div><Skeleton className="h-40 w-full bg-slate-800" /></div></CardContent></Card>;
}

function EmptyResults() {
  return <div className="flex min-h-44 items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-900/25 px-6 py-8 text-center"><div className="max-w-md"><Info className="mx-auto h-6 w-6 text-slate-500" aria-hidden="true" /><h2 className="mt-3 text-sm font-semibold text-slate-200">Results will appear here</h2><p className="mt-1 text-sm leading-6 text-slate-500">Analyze an email to see its verdict, risk, confidence, and supporting evidence.</p></div></div>;
}

function SectionHeading({ id, children, count }: { id: string; children: string; count?: number }) {
  return <h3 id={id} className="flex items-center gap-2 text-sm font-semibold text-slate-200">{children}{count !== undefined && <Badge variant="outline" className="border-slate-700 text-slate-500">{count}</Badge>}</h3>;
}

function RiskMeter({ score, classification }: { score: number; classification: ThreatClassification }) {
  const style = verdictStyles[classification];
  return (
    <div>
      <div className="relative pt-5" aria-label={`Risk score ${score} out of 100`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}>
        <span className="absolute top-0 -translate-x-1/2 text-[10px] font-semibold tabular-nums text-slate-300" style={{ left: `${Math.min(98, Math.max(2, score))}%` }}>{score}</span>
        <span className="absolute top-4 h-3 w-0.5 -translate-x-1/2 bg-white shadow" style={{ left: `${Math.min(99, Math.max(1, score))}%` }} />
        <div className="grid h-3 grid-cols-[30fr_40fr_30fr] gap-1 overflow-hidden rounded-full bg-slate-800"><span className="bg-emerald-500/70" /><span className="bg-amber-500/75" /><span className="bg-rose-500/80" /></div>
      </div>
      <div className="mt-2 grid grid-cols-[30fr_40fr_30fr] text-[10px] uppercase tracking-wide text-slate-500"><span>Safe</span><span className="text-center">Suspicious</span><span className="text-right">Phishing</span></div>
      <Progress value={score} className={cn('sr-only', style.progress)} />
    </div>
  );
}

function ConfidenceGauge({ value, color }: { value: number; color: string }) {
  const percent = Math.round(value * 100);
  return <div className="relative grid h-24 w-24 shrink-0 place-items-center rounded-full" role="meter" aria-label={`Decision confidence ${percent}%`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} style={{ background: `conic-gradient(${color} ${percent * 3.6}deg, rgb(30 41 59) 0deg)` }}><div className="grid h-[74px] w-[74px] place-items-center rounded-full bg-slate-950"><div className="text-center"><p className="text-xl font-semibold tabular-nums text-slate-100">{percent}%</p><p className="text-[9px] uppercase tracking-wide text-slate-500">confidence</p></div></div></div>;
}

function FindingCard({ signal }: { signal: ThreatSignal }) {
  const contextual = signal.score === 0;
  return (
    <article className="border-l-2 border-slate-700 pl-4">
      <div className="flex flex-wrap items-start justify-between gap-2"><div><p className="text-sm font-semibold text-slate-200">{signal.title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{signal.description}</p></div><Badge variant="outline" className={cn('shrink-0 capitalize', contextual ? 'border-slate-700 text-slate-400' : severityStyles[signal.severity])}>{contextual ? 'Context' : `${signal.severity} · +${signal.score}`}</Badge></div>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2"><div><dt className="text-slate-500">Evidence</dt><dd className="mt-1 break-words text-slate-300">{signal.evidence || 'Pattern-based detection'}</dd></div><div><dt className="text-slate-500">Source</dt><dd className="mt-1 capitalize text-slate-300">{signal.category}</dd></div></dl>
    </article>
  );
}

export function AnalysisResults({ result, isLoading = false }: { result: UnifiedAnalysisResponse | null; isLoading?: boolean }) {
  if (isLoading) return <LoadingResults />;
  if (!result) return <EmptyResults />;

  const style = verdictStyles[result.decision.classification];
  const VerdictIcon = style.icon;
  const materialSignals = result.rule_analysis.signals.filter((signal) => signal.score > 0).sort((a, b) => b.score - a.score);
  const topSignals = materialSignals.slice(0, 3);
  const remainingSignals = result.rule_analysis.signals.filter((signal) => !topSignals.includes(signal));
  const headerSignals = result.rule_analysis.signals.filter((signal) => signal.category === 'header');
  const completeness = result.analysis_completeness;
  const qualifiedSafe = result.decision.classification === 'safe' && completeness?.limited_evidence;
  const completenessLabel = completeness?.state.replaceAll('_', ' ') ?? 'not reported';
  const timeline = [
    { label: 'Input received', detail: 'Analysis request accepted' },
    { label: 'Parsed', detail: `${result.parser.extracted_urls.length} URLs · ${result.parser.attachments.length} attachments` },
    { label: 'Rules evaluated', detail: `${result.rule_analysis.signals.length} findings · ${result.rule_analysis.engine_version}` },
    { label: result.ml_analysis.status === 'available' ? 'ML evaluated' : 'ML unavailable', detail: result.ml_analysis.status === 'available' ? (result.ml_analysis.model_version || 'Model available') : 'Rule result remained available' },
    { label: 'Final decision', detail: `${result.decision.classification} · ${result.decision.risk_score}/100` },
  ];

  return (
    <div className="space-y-6" aria-live="polite">
      <Card className={cn('overflow-hidden border bg-slate-900/90', style.border)}>
        <CardContent className="p-0">
          <div className="grid xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="p-6 sm:p-8">
              <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex items-center gap-4"><span className={cn('flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-slate-950/60', style.text)}><VerdictIcon aria-hidden="true" /></span><div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Final verdict</p><h2 className={cn('mt-1 text-3xl font-semibold capitalize tracking-tight sm:text-4xl', style.text)}>{qualifiedSafe ? 'Safe based on limited evidence' : result.decision.classification}</h2></div></div>
                <Badge variant="outline" className={cn('w-fit', style.badge)}>{result.decision.risk_score >= 70 ? 'Immediate action' : result.decision.risk_score >= 30 ? 'Review advised' : 'Low concern'}</Badge>
              </div>
              {completeness?.warning && <div className="mt-5 flex gap-3 rounded-lg border border-amber-500/25 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" /><p>{completeness.warning}</p></div>}
              <div className="mt-7 rounded-lg border border-slate-800 bg-slate-950/45 p-4"><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Recommended action</p><p className="mt-2 text-base font-medium leading-7 text-slate-200">{result.recommendations[0] ?? 'Review with your security team.'}</p></div>
              <div className="mt-6"><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Top reasons</p>{topSignals.length ? <ul className="mt-3 grid gap-2 sm:grid-cols-3">{topSignals.map((signal) => <li key={signal.code} className="flex gap-2 text-sm leading-5 text-slate-300"><CircleDot className={cn('mt-0.5 h-4 w-4 shrink-0', signal.severity === 'high' ? 'text-rose-400' : signal.severity === 'medium' ? 'text-amber-400' : 'text-sky-400')} aria-hidden="true" /><span>{signal.title}</span></li>)}</ul> : <p className="mt-2 text-sm text-slate-400">No material threat signals detected.</p>}</div>
            </div>
            <aside className="border-t border-slate-800 bg-slate-950/40 p-6 sm:p-8 xl:border-l xl:border-t-0">
              <div className="flex items-center justify-between gap-5"><div><p className="text-xs uppercase tracking-wide text-slate-500">Risk score</p><p className="mt-1 text-4xl font-semibold tabular-nums text-slate-100">{result.decision.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></p></div><ConfidenceGauge value={result.decision.confidence} color={style.meter} /></div>
              <div className="mt-5"><RiskMeter score={result.decision.risk_score} classification={result.decision.classification} /></div>
            </aside>
          </div>
        </CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="border-b border-slate-800 pb-5"><h2 className="text-base font-semibold text-slate-100">Decision evidence</h2><p className="mt-1 text-sm text-slate-400">Separate outputs from fusion, rules, machine learning, and input completeness.</p></CardHeader>
        <CardContent className="grid gap-4 p-5 sm:grid-cols-2 sm:p-6 lg:grid-cols-4">
          <div className="rounded-lg bg-slate-950/45 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Final decision confidence</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{Math.round(result.decision.confidence * 100)}%</p></div>
          <div className="rounded-lg bg-slate-950/45 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Rule-based risk</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{result.rule_analysis.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></p></div>
          <div className="rounded-lg bg-slate-950/45 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">ML phishing probability</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{result.ml_analysis.phishing_probability === null ? 'Unavailable' : `${Math.round(result.ml_analysis.phishing_probability * 100)}%`}</p></div>
          <div className="rounded-lg bg-slate-950/45 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Analysis completeness</p><p className="mt-2 text-sm font-semibold capitalize text-slate-100">{completenessLabel}</p><Badge variant="outline" className={cn('mt-2', result.engine_agreement === 'disagreement' ? 'border-amber-500/30 text-amber-300' : 'border-slate-700 text-slate-400')}>{result.engine_agreement?.replaceAll('_', ' ') ?? 'agreement not reported'}</Badge></div>
        </CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="border-b border-slate-800 pb-5"><h2 className="flex items-center gap-2 text-base font-semibold text-slate-100"><Sparkles className="h-4 w-4 text-blue-400" aria-hidden="true" />Threat timeline</h2><p className="text-sm text-slate-400">A transparent view of the completed analysis stages.</p></CardHeader>
        <CardContent className="p-5 sm:p-6"><ol className="grid gap-0 sm:grid-cols-5">{timeline.map((step) => <li key={step.label} className="relative flex gap-3 pb-5 last:pb-0 sm:block sm:pb-0"><span className="absolute left-2 top-5 h-[calc(100%-12px)] w-px bg-slate-700 last:hidden sm:left-5 sm:top-2 sm:h-px sm:w-[calc(100%-16px)]" /><span className={cn('relative z-10 grid h-5 w-5 shrink-0 place-items-center rounded-full border', step.label === 'ML unavailable' ? 'border-amber-500/40 bg-amber-500/10 text-amber-300' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300')}>{step.label === 'ML unavailable' ? <Circle className="h-2 w-2 fill-current" /> : <Check className="h-3 w-3" />}</span><div className="sm:mt-3 sm:pr-4"><p className="text-xs font-medium text-slate-200">{step.label}</p><p className="mt-1 text-[11px] leading-4 text-slate-500">{step.detail}</p></div></li>)}</ol></CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="border-b border-slate-800 pb-5"><h2 className="text-base font-semibold text-slate-100">Explainability</h2><p className="mt-1 text-sm text-slate-400">The strongest evidence first, followed by supporting context.</p></CardHeader>
        <CardContent className="p-5 sm:p-6">
          {topSignals.length ? <div className="grid gap-6 lg:grid-cols-3">{topSignals.map((signal) => <FindingCard key={signal.code} signal={signal} />)}</div> : <p className="text-sm text-slate-500">No material threat findings require explanation.</p>}
          {remainingSignals.length > 0 && <div className="mt-6 border-t border-slate-800 pt-5"><SectionHeading id="supporting-evidence" count={remainingSignals.length}>Supporting findings</SectionHeading><div className="mt-3 divide-y divide-slate-800">{remainingSignals.map((signal, index) => <div key={`${signal.code}-${index}`} className="flex flex-col gap-2 py-3 first:pt-0 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium text-slate-300">{signal.title}</p><p className="mt-1 break-words text-xs text-slate-500">{signal.evidence || signal.description}</p></div><Badge variant="outline" className={cn('w-fit shrink-0 capitalize', signal.score === 0 ? 'border-slate-700 text-slate-400' : severityStyles[signal.severity])}>{signal.score === 0 ? 'Context' : `${signal.severity} · +${signal.score}`}</Badge></div>)}</div></div>}
        </CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="border-b border-slate-800 pb-5"><h2 className="text-base font-semibold text-slate-100">Analysis details</h2><p className="mt-1 text-sm text-slate-400">Parsed information and supporting investigation data.</p></CardHeader>
        <CardContent className="divide-y divide-slate-800 p-0">
          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-slate-800">
            <section aria-labelledby="urls-heading" className="p-5 sm:p-6"><SectionHeading id="urls-heading" count={result.parser.extracted_urls.length}>URLs</SectionHeading>{result.parser.extracted_urls.length ? <ul className="mt-4 space-y-2">{result.parser.extracted_urls.map((url, index) => <li key={`${url}-${index}`} className="flex min-w-0 gap-2 rounded-lg bg-slate-950/50 p-3 text-xs leading-5 text-slate-300"><ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden="true" /><span className="min-w-0 break-all">{url}</span></li>)}</ul> : <p className="mt-3 text-sm text-slate-500">No URLs extracted.</p>}</section>
            <section aria-labelledby="attachments-heading" className="border-t border-slate-800 p-5 sm:p-6 lg:border-t-0"><SectionHeading id="attachments-heading" count={result.parser.attachments.length}>Attachments</SectionHeading>{result.parser.attachments.length ? <ul className="mt-4 space-y-2">{result.parser.attachments.map((attachment, index) => <li key={`${attachment.filename}-${index}`} className="flex min-w-0 items-center justify-between gap-3 rounded-lg bg-slate-950/50 p-3"><div className="flex min-w-0 items-center gap-2">{isRisky(attachment) ? <FileWarning className="h-4 w-4 shrink-0 text-rose-400" aria-label="Risky extension" /> : <Paperclip className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />}<div className="min-w-0"><p className="truncate text-sm text-slate-300">{attachment.filename || 'Unnamed'}</p><p className="mt-0.5 truncate text-xs text-slate-500">{attachment.content_type || 'Unknown'} · {extensionOf(attachment.filename)}</p></div></div><span className="shrink-0 text-xs tabular-nums text-slate-500">{(attachment.size_bytes / 1024).toFixed(1)} KB</span></li>)}</ul> : <p className="mt-3 text-sm text-slate-500">No attachment metadata found.</p>}</section>
          </div>
          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-slate-800">
            <section aria-labelledby="metadata-heading" className="p-5 sm:p-6"><SectionHeading id="metadata-heading">Parsed metadata</SectionHeading><dl className="mt-4 space-y-3 text-sm">{[['Subject', result.parser.subject || '(No subject)'], ['Sender', result.parser.sender?.address || 'Not supplied'], ['Reply-To', result.parser.reply_to?.address || 'Not supplied'], ['Message-ID', result.parser.message_id || 'Not available']].map(([label, value]) => <div key={label} className="grid gap-1 sm:grid-cols-[90px_minmax(0,1fr)] sm:gap-3"><dt className="text-slate-500">{label}</dt><dd className="min-w-0 break-all text-slate-300">{value}</dd></div>)}</dl></section>
            <section aria-labelledby="recommendations-heading" className="border-t border-slate-800 p-5 sm:p-6 lg:border-t-0"><SectionHeading id="recommendations-heading">Recommendations</SectionHeading>{result.recommendations.length ? <ol className="mt-4 space-y-3">{result.recommendations.map((recommendation, index) => <li key={`${recommendation}-${index}`} className="flex gap-3 text-sm leading-6 text-slate-300"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 text-[10px] text-slate-400">{index + 1}</span>{recommendation}</li>)}</ol> : <p className="mt-3 text-sm text-slate-500">No additional recommendations.</p>}</section>
          </div>
          <section aria-labelledby="engine-heading" className="p-5 sm:p-6"><SectionHeading id="engine-heading">Engine metadata</SectionHeading><div className="mt-4 flex flex-wrap gap-2"><Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">Rules: {result.rule_analysis.engine_version}</Badge><Badge variant="outline" className={result.ml_analysis.status === 'available' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300'}>ML: {result.ml_analysis.status}</Badge><Badge variant="outline" className="border-slate-700 text-slate-400">Header findings: {headerSignals.length}</Badge></div></section>
        </CardContent>
      </Card>
    </div>
  );
}
