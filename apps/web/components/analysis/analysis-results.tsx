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
  safe: { text: 'text-success', border: 'border-success/30', badge: 'border-success/30 bg-success/10 text-success', progress: '[&>div]:bg-success', meter: '#10b981', icon: CheckCircle2 },
  suspicious: { text: 'text-warning', border: 'border-warning/30', badge: 'border-warning/30 bg-warning/10 text-warning', progress: '[&>div]:bg-warning', meter: '#f59e0b', icon: AlertTriangle },
  phishing: { text: 'text-danger', border: 'border-danger/30', badge: 'border-danger/30 bg-danger/10 text-danger', progress: '[&>div]:bg-danger', meter: '#f43f5e', icon: ShieldAlert },
};
const severityStyles: Record<ThreatSeverity, string> = {
  low: 'border-primary/30 bg-primary/10 text-primary',
  medium: 'border-warning/30 bg-warning/10 text-warning',
  high: 'border-danger/30 bg-danger/10 text-danger',
};

function extensionOf(filename: string | null) {
  return filename?.toLowerCase().match(/\.[^.]+$/)?.[0] ?? '—';
}

function isRisky(attachment: EmailAttachmentMetadata) {
  return attachment.suspicious_extension ?? riskyExtensions.includes(extensionOf(attachment.filename));
}

function LoadingResults() {
  return <Card className="border-border bg-surface/80" role="status" aria-live="polite" aria-label="Analysis in progress"><CardContent className="p-6 sm:p-8"><div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_300px]"><div className="space-y-4"><Skeleton className="h-4 w-28 bg-surface-muted" /><Skeleton className="h-10 w-48 bg-surface-muted" /><Skeleton className="h-20 w-full max-w-xl bg-surface-muted" /></div><Skeleton className="h-40 w-full bg-surface-muted" /></div></CardContent></Card>;
}

function EmptyResults() {
  return <div className="flex min-h-44 items-center justify-center rounded-xl border border-dashed border-border bg-surface/25 px-6 py-8 text-center"><div className="max-w-md"><Info className="mx-auto h-6 w-6 text-foreground0" aria-hidden="true" /><h2 className="mt-3 text-sm font-semibold text-foreground">Results will appear here</h2><p className="mt-1 text-sm leading-6 text-foreground0">Analyze an email to see its verdict, risk, confidence, and supporting evidence.</p></div></div>;
}

function SectionHeading({ id, children, count }: { id: string; children: string; count?: number }) {
  return <h3 id={id} className="flex items-center gap-2 text-sm font-semibold text-foreground">{children}{count !== undefined && <Badge variant="outline" className="border-input text-foreground0">{count}</Badge>}</h3>;
}

function RiskMeter({ score, classification }: { score: number; classification: ThreatClassification }) {
  const style = verdictStyles[classification];
  return (
    <div>
      <div className="relative pt-5" aria-label={`Risk score ${score} out of 100`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}>
        <span className="absolute top-0 -translate-x-1/2 text-[10px] font-semibold tabular-nums text-muted-foreground" style={{ left: `${Math.min(98, Math.max(2, score))}%` }}>{score}</span>
        <span className="absolute top-4 h-3 w-0.5 -translate-x-1/2 bg-white shadow" style={{ left: `${Math.min(99, Math.max(1, score))}%` }} />
        <div className="grid h-3 grid-cols-[30fr_40fr_30fr] gap-1 overflow-hidden rounded-full bg-surface-muted"><span className="bg-success/70" /><span className="bg-warning/75" /><span className="bg-danger/80" /></div>
      </div>
      <div className="mt-2 grid grid-cols-[30fr_40fr_30fr] text-[10px] uppercase tracking-wide text-foreground0"><span>Safe</span><span className="text-center">Suspicious</span><span className="text-right">Phishing</span></div>
      <Progress value={score} className={cn('sr-only', style.progress)} />
    </div>
  );
}

function ConfidenceGauge({ value, color }: { value: number; color: string }) {
  const percent = Math.round(value * 100);
  return <div className="relative grid h-24 w-24 shrink-0 place-items-center rounded-full" role="meter" aria-label={`Decision confidence ${percent}%`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} style={{ background: `conic-gradient(${color} ${percent * 3.6}deg, rgb(30 41 59) 0deg)` }}><div className="grid h-[74px] w-[74px] place-items-center rounded-full bg-background"><div className="text-center"><p className="text-xl font-semibold tabular-nums text-foreground">{percent}%</p><p className="text-[9px] uppercase tracking-wide text-foreground0">confidence</p></div></div></div>;
}

function FindingCard({ signal }: { signal: ThreatSignal }) {
  const contextual = signal.score === 0;
  return (
    <article className="border-l-2 border-input pl-4">
      <div className="flex flex-wrap items-start justify-between gap-2"><div><p className="text-sm font-semibold text-foreground">{signal.title}</p><p className="mt-1 text-sm leading-6 text-muted-foreground">{signal.description}</p></div><Badge variant="outline" className={cn('shrink-0 capitalize', contextual ? 'border-input text-muted-foreground' : severityStyles[signal.severity])}>{contextual ? 'Context' : `${signal.severity} · +${signal.score}`}</Badge></div>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2"><div><dt className="text-foreground0">Evidence</dt><dd className="mt-1 break-words text-muted-foreground">{signal.evidence || 'Pattern-based detection'}</dd></div><div><dt className="text-foreground0">Source</dt><dd className="mt-1 capitalize text-muted-foreground">{signal.category}</dd></div></dl>
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
      <Card className={cn('overflow-hidden border bg-surface/90', style.border)}>
        <CardContent className="p-0">
          <div className="grid xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="p-6 sm:p-8">
              <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex items-center gap-4"><span className={cn('flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-background/60', style.text)}><VerdictIcon aria-hidden="true" /></span><div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-foreground0">Final verdict</p><h2 className={cn('mt-1 text-3xl font-semibold capitalize tracking-tight sm:text-4xl', style.text)}>{qualifiedSafe ? 'Safe based on limited evidence' : result.decision.classification}</h2></div></div>
                <Badge variant="outline" className={cn('w-fit', style.badge)}>{result.decision.risk_score >= 70 ? 'Immediate action' : result.decision.risk_score >= 30 ? 'Review advised' : 'Low concern'}</Badge>
              </div>
              {completeness?.warning && <div className="mt-5 flex gap-3 rounded-lg border border-warning/25 bg-warning/10 p-4 text-sm leading-6 text-warning"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden="true" /><p>{completeness.warning}</p></div>}
              <div className="mt-7 rounded-lg border border-border bg-background/45 p-4"><p className="text-xs font-medium uppercase tracking-wide text-foreground0">Recommended action</p><p className="mt-2 text-base font-medium leading-7 text-foreground">{result.recommendations[0] ?? 'Review with your security team.'}</p></div>
              <div className="mt-6"><p className="text-xs font-medium uppercase tracking-wide text-foreground0">Top reasons</p>{topSignals.length ? <ul className="mt-3 grid gap-2 sm:grid-cols-3">{topSignals.map((signal) => <li key={signal.code} className="flex gap-2 text-sm leading-5 text-muted-foreground"><CircleDot className={cn('mt-0.5 h-4 w-4 shrink-0', signal.severity === 'high' ? 'text-danger' : signal.severity === 'medium' ? 'text-warning' : 'text-primary')} aria-hidden="true" /><span>{signal.title}</span></li>)}</ul> : <p className="mt-2 text-sm text-muted-foreground">No material threat signals detected.</p>}</div>
            </div>
            <aside className="border-t border-border bg-background/40 p-6 sm:p-8 xl:border-l xl:border-t-0">
              <div className="flex items-center justify-between gap-5"><div><p className="text-xs uppercase tracking-wide text-foreground0">Risk score</p><p className="mt-1 text-4xl font-semibold tabular-nums text-foreground">{result.decision.risk_score}<span className="text-sm font-normal text-foreground0">/100</span></p></div><ConfidenceGauge value={result.decision.confidence} color={style.meter} /></div>
              <div className="mt-5"><RiskMeter score={result.decision.risk_score} classification={result.decision.classification} /></div>
            </aside>
          </div>
        </CardContent>
      </Card>

      <Card className="border-border bg-surface/80">
        <CardHeader className="border-b border-border pb-5"><h2 className="text-base font-semibold text-foreground">Decision evidence</h2><p className="mt-1 text-sm text-muted-foreground">Separate outputs from fusion, rules, machine learning, and input completeness.</p></CardHeader>
        <CardContent className="grid gap-4 p-5 sm:grid-cols-2 sm:p-6 lg:grid-cols-4">
          <div className="rounded-lg bg-background/45 p-4"><p className="text-xs uppercase tracking-wide text-foreground0">Final decision confidence</p><p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{Math.round(result.decision.confidence * 100)}%</p></div>
          <div className="rounded-lg bg-background/45 p-4"><p className="text-xs uppercase tracking-wide text-foreground0">Rule-based risk</p><p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{result.rule_analysis.risk_score}<span className="text-sm font-normal text-foreground0">/100</span></p></div>
          <div className="rounded-lg bg-background/45 p-4"><p className="text-xs uppercase tracking-wide text-foreground0">ML phishing probability</p><p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{result.ml_analysis.phishing_probability === null ? 'Unavailable' : `${Math.round(result.ml_analysis.phishing_probability * 100)}%`}</p></div>
          <div className="rounded-lg bg-background/45 p-4"><p className="text-xs uppercase tracking-wide text-foreground0">Analysis completeness</p><p className="mt-2 text-sm font-semibold capitalize text-foreground">{completenessLabel}</p><Badge variant="outline" className={cn('mt-2', result.engine_agreement === 'disagreement' ? 'border-warning/30 text-warning' : 'border-input text-muted-foreground')}>{result.engine_agreement?.replaceAll('_', ' ') ?? 'agreement not reported'}</Badge></div>
        </CardContent>
      </Card>

      <Card className="border-border bg-surface/80">
        <CardHeader className="border-b border-border pb-5"><h2 className="flex items-center gap-2 text-base font-semibold text-foreground"><Sparkles className="h-4 w-4 text-primary" aria-hidden="true" />Threat timeline</h2><p className="text-sm text-muted-foreground">A transparent view of the completed analysis stages.</p></CardHeader>
        <CardContent className="p-5 sm:p-6"><ol className="grid gap-0 sm:grid-cols-5">{timeline.map((step) => <li key={step.label} className="relative flex gap-3 pb-5 last:pb-0 sm:block sm:pb-0"><span className="absolute left-2 top-5 h-[calc(100%-12px)] w-px bg-surface-muted last:hidden sm:left-5 sm:top-2 sm:h-px sm:w-[calc(100%-16px)]" /><span className={cn('relative z-10 grid h-5 w-5 shrink-0 place-items-center rounded-full border', step.label === 'ML unavailable' ? 'border-warning/40 bg-warning/10 text-warning' : 'border-success/40 bg-success/10 text-success')}>{step.label === 'ML unavailable' ? <Circle className="h-2 w-2 fill-current" /> : <Check className="h-3 w-3" />}</span><div className="sm:mt-3 sm:pr-4"><p className="text-xs font-medium text-foreground">{step.label}</p><p className="mt-1 text-[11px] leading-4 text-foreground0">{step.detail}</p></div></li>)}</ol></CardContent>
      </Card>

      <Card className="border-border bg-surface/80">
        <CardHeader className="border-b border-border pb-5"><h2 className="text-base font-semibold text-foreground">Explainability</h2><p className="mt-1 text-sm text-muted-foreground">The strongest evidence first, followed by supporting context.</p></CardHeader>
        <CardContent className="p-5 sm:p-6">
          {topSignals.length ? <div className="grid gap-6 lg:grid-cols-3">{topSignals.map((signal) => <FindingCard key={signal.code} signal={signal} />)}</div> : <p className="text-sm text-foreground0">No material threat findings require explanation.</p>}
          {remainingSignals.length > 0 && <div className="mt-6 border-t border-border pt-5"><SectionHeading id="supporting-evidence" count={remainingSignals.length}>Supporting findings</SectionHeading><div className="mt-3 divide-y divide-border">{remainingSignals.map((signal, index) => <div key={`${signal.code}-${index}`} className="flex flex-col gap-2 py-3 first:pt-0 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium text-muted-foreground">{signal.title}</p><p className="mt-1 break-words text-xs text-foreground0">{signal.evidence || signal.description}</p></div><Badge variant="outline" className={cn('w-fit shrink-0 capitalize', signal.score === 0 ? 'border-input text-muted-foreground' : severityStyles[signal.severity])}>{signal.score === 0 ? 'Context' : `${signal.severity} · +${signal.score}`}</Badge></div>)}</div></div>}
        </CardContent>
      </Card>

      <Card className="border-border bg-surface/80">
        <CardHeader className="border-b border-border pb-5"><h2 className="text-base font-semibold text-foreground">Analysis details</h2><p className="mt-1 text-sm text-muted-foreground">Parsed information and supporting investigation data.</p></CardHeader>
        <CardContent className="divide-y divide-border p-0">
          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-border">
            <section aria-labelledby="urls-heading" className="p-5 sm:p-6"><SectionHeading id="urls-heading" count={result.parser.extracted_urls.length}>URLs</SectionHeading>{result.parser.extracted_urls.length ? <ul className="mt-4 space-y-2">{result.parser.extracted_urls.map((url, index) => <li key={`${url}-${index}`} className="flex min-w-0 gap-2 rounded-lg bg-background/50 p-3 text-xs leading-5 text-muted-foreground"><ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-foreground0" aria-hidden="true" /><span className="min-w-0 break-all">{url}</span></li>)}</ul> : <p className="mt-3 text-sm text-foreground0">No URLs extracted.</p>}</section>
            <section aria-labelledby="attachments-heading" className="border-t border-border p-5 sm:p-6 lg:border-t-0"><SectionHeading id="attachments-heading" count={result.parser.attachments.length}>Attachments</SectionHeading>{result.parser.attachments.length ? <ul className="mt-4 space-y-2">{result.parser.attachments.map((attachment, index) => <li key={`${attachment.filename}-${index}`} className="flex min-w-0 items-center justify-between gap-3 rounded-lg bg-background/50 p-3"><div className="flex min-w-0 items-center gap-2">{isRisky(attachment) ? <FileWarning className="h-4 w-4 shrink-0 text-danger" aria-label="Risky extension" /> : <Paperclip className="h-4 w-4 shrink-0 text-foreground0" aria-hidden="true" />}<div className="min-w-0"><p className="truncate text-sm text-muted-foreground">{attachment.filename || 'Unnamed'}</p><p className="mt-0.5 truncate text-xs text-foreground0">{attachment.content_type || 'Unknown'} · {extensionOf(attachment.filename)}</p></div></div><span className="shrink-0 text-xs tabular-nums text-foreground0">{(attachment.size_bytes / 1024).toFixed(1)} KB</span></li>)}</ul> : <p className="mt-3 text-sm text-foreground0">No attachment metadata found.</p>}</section>
          </div>
          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-border">
            <section aria-labelledby="metadata-heading" className="p-5 sm:p-6"><SectionHeading id="metadata-heading">Parsed metadata</SectionHeading><dl className="mt-4 space-y-3 text-sm">{[['Subject', result.parser.subject || '(No subject)'], ['Sender', result.parser.sender?.address || 'Not supplied'], ['Reply-To', result.parser.reply_to?.address || 'Not supplied'], ['Message-ID', result.parser.message_id || 'Not available']].map(([label, value]) => <div key={label} className="grid gap-1 sm:grid-cols-[90px_minmax(0,1fr)] sm:gap-3"><dt className="text-foreground0">{label}</dt><dd className="min-w-0 break-all text-muted-foreground">{value}</dd></div>)}</dl></section>
            <section aria-labelledby="recommendations-heading" className="border-t border-border p-5 sm:p-6 lg:border-t-0"><SectionHeading id="recommendations-heading">Recommendations</SectionHeading>{result.recommendations.length ? <ol className="mt-4 space-y-3">{result.recommendations.map((recommendation, index) => <li key={`${recommendation}-${index}`} className="flex gap-3 text-sm leading-6 text-muted-foreground"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-muted text-[10px] text-muted-foreground">{index + 1}</span>{recommendation}</li>)}</ol> : <p className="mt-3 text-sm text-foreground0">No additional recommendations.</p>}</section>
          </div>
          <section aria-labelledby="engine-heading" className="p-5 sm:p-6"><SectionHeading id="engine-heading">Engine metadata</SectionHeading><div className="mt-4 flex flex-wrap gap-2"><Badge variant="outline" className="border-success/30 bg-success/10 text-success">Rules: {result.rule_analysis.engine_version}</Badge><Badge variant="outline" className={result.ml_analysis.status === 'available' ? 'border-success/30 bg-success/10 text-success' : 'border-warning/30 bg-warning/10 text-warning'}>ML: {result.ml_analysis.status}</Badge><Badge variant="outline" className="border-input text-muted-foreground">Header findings: {headerSignals.length}</Badge></div></section>
        </CardContent>
      </Card>
    </div>
  );
}
