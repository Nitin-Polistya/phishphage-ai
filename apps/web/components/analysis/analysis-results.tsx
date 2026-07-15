import { AlertTriangle, CheckCircle2, Circle, ExternalLink, FileWarning, Info, Link as LinkIcon, Paperclip, ShieldAlert } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import type { EmailAttachmentMetadata, ThreatClassification, ThreatSeverity, UnifiedAnalysisResponse } from '@/types/analysis';

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
  return match?.[0] ?? '—';
}

function isRisky(attachment: EmailAttachmentMetadata) {
  return attachment.suspicious_extension ?? riskyExtensions.includes(extensionOf(attachment.filename));
}

function LoadingResults() {
  return <Card className="min-h-[520px] border-slate-800 bg-slate-900/80"><CardContent className="space-y-5 p-6" aria-busy="true"><Skeleton className="h-5 w-28 bg-slate-800" /><Skeleton className="h-12 w-48 bg-slate-800" /><Skeleton className="h-3 w-full bg-slate-800" /><Separator className="bg-slate-800" />{[1, 2, 3].map((item) => <Skeleton key={item} className="h-16 w-full bg-slate-800" />)}</CardContent></Card>;
}

function EmptyResults() {
  return <Card className="flex min-h-[520px] items-center justify-center border-dashed border-slate-800 bg-slate-900/40"><CardContent className="max-w-sm p-8 text-center"><div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-slate-800 bg-slate-950"><Info className="text-slate-500" aria-hidden="true" /></div><h2 className="mt-4 font-medium text-slate-200">Awaiting analysis</h2><p className="mt-2 text-sm leading-6 text-slate-500">Choose an input method and submit an email. The verdict and priority findings will appear here.</p></CardContent></Card>;
}

export function AnalysisResults({ result, isLoading = false }: { result: UnifiedAnalysisResponse | null; isLoading?: boolean }) {
  if (isLoading) return <LoadingResults />;
  if (!result) return <EmptyResults />;

  const style = verdictStyles[result.decision.classification];
  const VerdictIcon = style.icon;
  const topSignals = [...result.rule_analysis.signals].filter((signal) => signal.score > 0).sort((a, b) => b.score - a.score).slice(0, 3);

  return (
    <div className="space-y-6">
      <Card className={cn('border bg-slate-900/90', style.border)} aria-live="polite">
        <CardHeader className="pb-4">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3"><VerdictIcon className={style.text} aria-hidden="true" /><div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Final verdict</p><CardTitle className={cn('mt-1 text-2xl capitalize', style.text)}>{result.decision.classification}</CardTitle></div></div>
            <Badge variant="outline" className={style.badge}>{result.decision.risk_score >= 70 ? 'Immediate action' : result.decision.risk_score >= 30 ? 'Review advised' : 'Low concern'}</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div><div className="mb-2 flex items-end justify-between"><span className="text-sm text-slate-400">Risk score</span><span className="text-3xl font-semibold tabular-nums text-slate-100">{result.decision.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></span></div><Progress value={result.decision.risk_score} className={cn('h-2 bg-slate-800', style.progress)} aria-label={`Risk score ${result.decision.risk_score} out of 100`} /></div>
          <div className="grid grid-cols-2 gap-4"><div><p className="text-xs text-slate-500">Confidence</p><p className="mt-1 text-lg font-semibold text-slate-200">{Math.round(result.decision.confidence * 100)}%</p></div><div><p className="text-xs text-slate-500">Recommended action</p><p className="mt-1 text-sm font-medium text-slate-200">{result.recommendations[0] ?? 'Review with your security team.'}</p></div></div>
          <Separator className="bg-slate-800" />
          <div><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Top reasons</p>{topSignals.length ? <ul className="mt-3 space-y-2">{topSignals.map((signal) => <li key={signal.code} className="flex items-start gap-2 text-sm text-slate-300"><Circle className="mt-1 h-2 w-2 shrink-0 fill-current text-slate-500" aria-hidden="true" /><span>{signal.title} <span className="text-slate-500">(+{signal.score})</span></span></li>)}</ul> : <p className="mt-2 text-sm text-slate-400">No material threat signals detected.</p>}</div>
          <div className="flex flex-wrap gap-2 border-t border-slate-800 pt-4"><Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">Rule engine: Active</Badge><Badge variant="outline" className="border-slate-700 bg-slate-950 text-slate-400">ML engine: {result.ml_analysis.status === 'available' ? 'Available' : 'Unavailable'}</Badge></div>
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card className="border-slate-800 bg-slate-900/80 xl:col-span-2"><CardHeader><CardTitle className="text-base text-slate-100">Detected indicators</CardTitle></CardHeader><CardContent>{result.rule_analysis.signals.length ? <div className="space-y-4">{result.rule_analysis.signals.map((signal, index) => { const contextual = signal.code === 'SELF_ADDRESSED_EMAIL'; return <div key={signal.code}>{index > 0 && <Separator className="mb-4 bg-slate-800" />}<div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-slate-200">{contextual ? 'Self-addressed message' : signal.title}</p><p className="mt-1 text-sm leading-5 text-slate-400">{signal.description}</p></div><Badge variant="outline" className={cn('shrink-0 capitalize', contextual ? 'border-slate-700 bg-slate-950 text-slate-400' : severityStyles[signal.severity])}>{contextual ? 'Context' : `${signal.severity} · +${signal.score}`}</Badge></div><div className="mt-2 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs"><span className="text-slate-500">Found in {signal.category}: </span><span className="break-words text-slate-300">{signal.evidence || 'Pattern-based detection'}</span></div></div>; })}</div> : <p className="text-sm text-slate-500">No indicators detected.</p>}</CardContent></Card>

        <Card className="border-slate-800 bg-slate-900/80"><CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><LinkIcon className="h-4 w-4 text-slate-500" />URLs</CardTitle></CardHeader><CardContent>{result.parser.extracted_urls.length ? <ul className="space-y-2">{result.parser.extracted_urls.map((url) => <li key={url} className="flex gap-2 break-all rounded-md border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-300"><ExternalLink className="h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden="true" />{url}</li>)}</ul> : <p className="text-sm text-slate-500">No URLs extracted.</p>}</CardContent></Card>

        <Card className="border-slate-800 bg-slate-900/80"><CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Paperclip className="h-4 w-4 text-slate-500" />Attachments</CardTitle></CardHeader><CardContent className="px-0">{result.parser.attachments.length ? <Table><TableHeader><TableRow className="border-slate-800"><TableHead className="text-slate-500">File</TableHead><TableHead className="text-slate-500">Type</TableHead><TableHead className="text-right text-slate-500">Size</TableHead></TableRow></TableHeader><TableBody>{result.parser.attachments.map((attachment, index) => <TableRow key={`${attachment.filename}-${index}`} className="border-slate-800"><TableCell className="text-slate-300"><span className="flex items-center gap-2">{isRisky(attachment) && <FileWarning className="h-4 w-4 text-rose-400" aria-label="Risky extension" />}{attachment.filename || 'Unnamed'} <span className="text-xs text-slate-600">{extensionOf(attachment.filename)}</span></span></TableCell><TableCell className="text-xs text-slate-400">{attachment.content_type || 'Unknown'}</TableCell><TableCell className="text-right text-xs tabular-nums text-slate-400">{(attachment.size_bytes / 1024).toFixed(1)} KB</TableCell></TableRow>)}</TableBody></Table> : <p className="px-6 text-sm text-slate-500">No attachment metadata found.</p>}</CardContent></Card>

        <Card className="border-slate-800 bg-slate-900/80"><CardHeader><CardTitle className="text-base text-slate-100">Recommendations</CardTitle></CardHeader><CardContent><ol className="space-y-3">{result.recommendations.map((recommendation, index) => <li key={recommendation} className="flex gap-3 text-sm leading-5 text-slate-300"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 text-[10px] text-slate-400">{index + 1}</span>{recommendation}</li>)}</ol></CardContent></Card>

        <Card className="border-slate-800 bg-slate-900/80"><CardHeader><CardTitle className="text-base text-slate-100">Parsed metadata</CardTitle></CardHeader><CardContent><dl className="space-y-3 text-sm">{[['Subject', result.parser.subject || '(No subject)'], ['Sender', result.parser.sender?.address || 'Not supplied'], ['Reply-To', result.parser.reply_to?.address || 'Not supplied'], ['Message-ID', result.parser.message_id || 'Not available']].map(([label, value]) => <div key={label} className="grid grid-cols-[90px_1fr] gap-3"><dt className="text-slate-500">{label}</dt><dd className="break-all text-slate-300">{value}</dd></div>)}</dl></CardContent></Card>

        <Card className="border-slate-800 bg-slate-900/80"><CardHeader><CardTitle className="text-base text-slate-100">Header findings</CardTitle></CardHeader><CardContent>{result.rule_analysis.signals.filter((signal) => signal.category === 'header').length ? <ul className="space-y-2 text-sm text-slate-300">{result.rule_analysis.signals.filter((signal) => signal.category === 'header').map((signal) => <li key={signal.code}>{signal.title}</li>)}</ul> : <p className="text-sm text-slate-500">No header findings for this input mode.</p>}</CardContent></Card>
      </div>
    </div>
  );
}
