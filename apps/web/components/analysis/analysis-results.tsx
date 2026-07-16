import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  ExternalLink,
  FileWarning,
  Info,
  Paperclip,
  ShieldAlert,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import type {
  EmailAttachmentMetadata,
  ThreatClassification,
  ThreatSeverity,
  UnifiedAnalysisResponse,
} from '@/types/analysis';

const riskyExtensions = ['.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.iso', '.img', '.zip', '.rar', '.docm', '.xlsm', '.pptm'];
const verdictStyles: Record<ThreatClassification, { text: string; border: string; badge: string; progress: string; icon: typeof CheckCircle2 }> = {
  safe: { text: 'text-emerald-300', border: 'border-emerald-500/30', badge: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300', progress: '[&>div]:bg-emerald-500', icon: CheckCircle2 },
  suspicious: { text: 'text-amber-300', border: 'border-amber-500/30', badge: 'border-amber-500/30 bg-amber-500/10 text-amber-300', progress: '[&>div]:bg-amber-500', icon: AlertTriangle },
  phishing: { text: 'text-rose-300', border: 'border-rose-500/30', badge: 'border-rose-500/30 bg-rose-500/10 text-rose-300', progress: '[&>div]:bg-rose-500', icon: ShieldAlert },
};
const severityStyles: Record<ThreatSeverity, string> = {
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  high: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
};

function extensionOf(filename: string | null) {
  const match = filename?.toLowerCase().match(/\.[^.]+$/);
  return match?.[0] ?? '--';
}

function isRisky(attachment: EmailAttachmentMetadata) {
  return attachment.suspicious_extension ?? riskyExtensions.includes(extensionOf(attachment.filename));
}

function LoadingResults() {
  return (
    <Card className="border-slate-800 bg-slate-900/80" role="status" aria-live="polite" aria-label="Analysis in progress">
      <CardContent className="p-6 sm:p-8">
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_240px]">
          <div className="space-y-4"><Skeleton className="h-4 w-28 bg-slate-800" /><Skeleton className="h-10 w-48 bg-slate-800" /><Skeleton className="h-16 w-full max-w-xl bg-slate-800" /></div>
          <div className="space-y-3"><Skeleton className="h-16 w-full bg-slate-800" /><Skeleton className="h-10 w-full bg-slate-800" /></div>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyResults() {
  return (
    <div className="flex min-h-44 items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-900/25 px-6 py-8 text-center">
      <div className="max-w-md"><Info className="mx-auto h-6 w-6 text-slate-500" aria-hidden="true" /><h2 className="mt-3 text-sm font-semibold text-slate-200">Results will appear here</h2><p className="mt-1 text-sm leading-6 text-slate-500">Choose an input method and analyze an email to see its verdict, risk, and supporting evidence.</p></div>
    </div>
  );
}

function SectionHeading({ id, children, count }: { id: string; children: string; count?: number }) {
  return <h3 id={id} className="flex items-center gap-2 text-sm font-semibold text-slate-200">{children}{count !== undefined && <Badge variant="outline" className="border-slate-700 text-slate-500">{count}</Badge>}</h3>;
}

export function AnalysisResults({ result, isLoading = false }: { result: UnifiedAnalysisResponse | null; isLoading?: boolean }) {
  if (isLoading) return <LoadingResults />;
  if (!result) return <EmptyResults />;

  const style = verdictStyles[result.decision.classification];
  const VerdictIcon = style.icon;
  const topSignals = [...result.rule_analysis.signals].filter((signal) => signal.score > 0).sort((a, b) => b.score - a.score).slice(0, 3);
  const headerSignals = result.rule_analysis.signals.filter((signal) => signal.category === 'header');

  return (
    <div className="space-y-6" aria-live="polite">
      <Card className={cn('overflow-hidden border bg-slate-900/90', style.border)}>
        <CardContent className="p-0">
          <div className="grid lg:grid-cols-[minmax(0,1fr)_300px]">
            <div className="p-6 sm:p-8">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex items-center gap-3">
                  <span className={cn('flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-950/60', style.text)}><VerdictIcon aria-hidden="true" /></span>
                  <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Final verdict</p><h2 className={cn('mt-1 text-3xl font-semibold capitalize tracking-tight', style.text)}>{result.decision.classification}</h2></div>
                </div>
                <Badge variant="outline" className={cn('w-fit', style.badge)}>{result.decision.risk_score >= 70 ? 'Immediate action' : result.decision.risk_score >= 30 ? 'Review advised' : 'Low concern'}</Badge>
              </div>

              <div className="mt-7 grid gap-5 sm:grid-cols-2">
                <div><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Recommended action</p><p className="mt-2 text-base font-medium leading-6 text-slate-200">{result.recommendations[0] ?? 'Review with your security team.'}</p></div>
                <div><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Top reasons</p>{topSignals.length ? <ul className="mt-2 space-y-2">{topSignals.map((signal) => <li key={signal.code} className="flex items-start gap-2 text-sm text-slate-300"><Circle className="mt-1.5 h-2 w-2 shrink-0 fill-current text-slate-500" aria-hidden="true" /><span>{signal.title} <span className="whitespace-nowrap text-slate-500">(+{signal.score})</span></span></li>)}</ul> : <p className="mt-2 text-sm text-slate-400">No material threat signals detected.</p>}</div>
              </div>
            </div>

            <div className="border-t border-slate-800 bg-slate-950/40 p-6 lg:border-l lg:border-t-0 sm:p-8">
              <div className="flex items-end justify-between gap-4"><span className="text-sm text-slate-400">Risk score</span><span className="text-4xl font-semibold tabular-nums text-slate-100">{result.decision.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></span></div>
              <Progress value={result.decision.risk_score} className={cn('mt-3 h-2 bg-slate-800', style.progress)} aria-label={`Risk score ${result.decision.risk_score} out of 100`} />
              <Separator className="my-5 bg-slate-800" />
              <div className="flex items-end justify-between gap-4"><span className="text-sm text-slate-400">Confidence</span><span className="text-2xl font-semibold tabular-nums text-slate-200">{Math.round(result.decision.confidence * 100)}%</span></div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-slate-800 bg-slate-900/80">
        <CardHeader className="border-b border-slate-800 pb-5"><div><h2 className="text-base font-semibold text-slate-100">Analysis details</h2><p className="mt-1 text-sm text-slate-400">Evidence and parsed information supporting the verdict.</p></div></CardHeader>
        <CardContent className="divide-y divide-slate-800 p-0">
          <section aria-labelledby="indicators-heading" className="p-5 sm:p-6">
            <h3 id="indicators-heading" className="flex items-center gap-2 text-sm font-semibold text-slate-200">Detected indicators <Badge variant="outline" className="border-slate-700 text-slate-500">{result.rule_analysis.signals.length}</Badge></h3>
            {result.rule_analysis.signals.length ? <div className="mt-4 space-y-4">{result.rule_analysis.signals.map((signal, index) => { const contextual = signal.code === 'SELF_ADDRESSED_EMAIL'; return <div key={`${signal.code}-${index}`} className="rounded-lg bg-slate-950/50 p-4"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><p className="text-sm font-medium text-slate-200">{contextual ? 'Self-addressed message' : signal.title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{signal.description}</p></div><Badge variant="outline" className={cn('w-fit shrink-0 capitalize', contextual ? 'border-slate-700 bg-slate-950 text-slate-400' : severityStyles[signal.severity])}>{contextual ? 'Context' : `${signal.severity} - +${signal.score}`}</Badge></div><p className="mt-3 break-words text-xs leading-5 text-slate-400"><span className="text-slate-500">Found in {signal.category}: </span>{signal.evidence || 'Pattern-based detection'}</p></div>; })}</div> : <p className="mt-3 text-sm text-slate-500">No indicators detected.</p>}
          </section>

          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-slate-800">
            <section aria-labelledby="urls-heading" className="p-5 sm:p-6">
              <SectionHeading id="urls-heading" count={result.parser.extracted_urls.length}>URLs</SectionHeading>
              {result.parser.extracted_urls.length ? <ul className="mt-4 space-y-2">{result.parser.extracted_urls.map((url, index) => <li key={`${url}-${index}`} className="flex min-w-0 gap-2 rounded-lg bg-slate-950/50 p-3 text-xs leading-5 text-slate-300"><ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden="true" /><span className="min-w-0 break-all">{url}</span></li>)}</ul> : <p className="mt-3 text-sm text-slate-500">No URLs extracted.</p>}
            </section>

            <section aria-labelledby="attachments-heading" className="border-t border-slate-800 p-5 sm:p-6 lg:border-t-0">
              <SectionHeading id="attachments-heading" count={result.parser.attachments.length}>Attachments</SectionHeading>
              {result.parser.attachments.length ? <ul className="mt-4 space-y-2">{result.parser.attachments.map((attachment, index) => <li key={`${attachment.filename}-${index}`} className="flex min-w-0 items-center justify-between gap-3 rounded-lg bg-slate-950/50 p-3"><div className="flex min-w-0 items-center gap-2">{isRisky(attachment) ? <FileWarning className="h-4 w-4 shrink-0 text-rose-400" aria-label="Risky extension" /> : <Paperclip className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />}<div className="min-w-0"><p className="truncate text-sm text-slate-300" title={attachment.filename ?? undefined}>{attachment.filename || 'Unnamed'}</p><p className="mt-0.5 truncate text-xs text-slate-500">{attachment.content_type || 'Unknown'} - {extensionOf(attachment.filename)}</p></div></div><span className="shrink-0 text-xs tabular-nums text-slate-500">{(attachment.size_bytes / 1024).toFixed(1)} KB</span></li>)}</ul> : <p className="mt-3 text-sm text-slate-500">No attachment metadata found.</p>}
            </section>
          </div>

          <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-slate-800">
            <section aria-labelledby="metadata-heading" className="p-5 sm:p-6">
              <SectionHeading id="metadata-heading">Parsed metadata</SectionHeading>
              <dl className="mt-4 space-y-3 text-sm">{[
                ['Subject', result.parser.subject || '(No subject)'],
                ['Sender', result.parser.sender?.address || 'Not supplied'],
                ['Reply-To', result.parser.reply_to?.address || 'Not supplied'],
                ['Message-ID', result.parser.message_id || 'Not available'],
              ].map(([label, value]) => <div key={label} className="grid gap-1 sm:grid-cols-[90px_minmax(0,1fr)] sm:gap-3"><dt className="text-slate-500">{label}</dt><dd className="min-w-0 break-all text-slate-300">{value}</dd></div>)}</dl>
            </section>

            <section aria-labelledby="recommendations-heading" className="border-t border-slate-800 p-5 sm:p-6 lg:border-t-0">
              <SectionHeading id="recommendations-heading">Recommendations</SectionHeading>
              {result.recommendations.length ? <ol className="mt-4 space-y-3">{result.recommendations.map((recommendation, index) => <li key={`${recommendation}-${index}`} className="flex gap-3 text-sm leading-6 text-slate-300"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 text-[10px] text-slate-400">{index + 1}</span><span>{recommendation}</span></li>)}</ol> : <p className="mt-3 text-sm text-slate-500">No additional recommendations.</p>}
            </section>
          </div>

          <section aria-labelledby="engine-heading" className="p-5 sm:p-6">
            <SectionHeading id="engine-heading">Engine status</SectionHeading>
            <div className="mt-4 flex flex-wrap gap-2"><Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">Rule engine: Active</Badge><Badge variant="outline" className={result.ml_analysis.status === 'available' ? 'border-slate-700 bg-slate-950 text-slate-400' : 'border-amber-500/20 bg-amber-500/5 text-slate-400'}>ML engine: {result.ml_analysis.status === 'available' ? 'Available' : 'Unavailable'}</Badge></div>
            {result.ml_analysis.status === 'unavailable' && <p className="mt-3 text-xs leading-5 text-slate-500">The verdict remains available from the rule engine. ML enrichment was not available for this analysis.</p>}
            <div className="mt-4 rounded-lg bg-slate-950/50 p-4"><p className="text-xs font-medium uppercase tracking-wide text-slate-500">Mode-aware header checks</p><p className="mt-1 text-sm text-slate-400">{headerSignals.length ? `${headerSignals.length} header finding${headerSignals.length === 1 ? '' : 's'} contributed to this analysis.` : 'No header findings were available for this input mode.'}</p></div>
          </section>
        </CardContent>
      </Card>
    </div>
  );
}
