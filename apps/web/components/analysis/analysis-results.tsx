import {
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  Info,
  Link as LinkIcon,
  Mail,
  Paperclip,
  ShieldAlert,
  Users,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { ThreatClassification, ThreatSeverity, UnifiedAnalysisResponse } from '@/types/analysis';

const classificationStyles: Record<ThreatClassification, { panel: string; text: string; badge: string; progress: string; icon: typeof CheckCircle2 }> = {
  safe: {
    panel: 'border-green-200 bg-green-50',
    text: 'text-green-700',
    badge: 'border-green-200 bg-green-100 text-green-800',
    progress: '[&>div]:bg-green-600',
    icon: CheckCircle2,
  },
  suspicious: {
    panel: 'border-amber-200 bg-amber-50',
    text: 'text-amber-700',
    badge: 'border-amber-200 bg-amber-100 text-amber-800',
    progress: '[&>div]:bg-amber-500',
    icon: AlertTriangle,
  },
  phishing: {
    panel: 'border-red-200 bg-red-50',
    text: 'text-red-700',
    badge: 'border-red-200 bg-red-100 text-red-800',
    progress: '[&>div]:bg-red-600',
    icon: ShieldAlert,
  },
};

const severityStyles: Record<ThreatSeverity, string> = {
  low: 'border-slate-200 bg-slate-100 text-slate-700',
  medium: 'border-amber-200 bg-amber-100 text-amber-800',
  high: 'border-red-200 bg-red-100 text-red-800',
};

function EmptyResults() {
  return (
    <div className="flex h-full min-h-[420px] flex-col items-center justify-center space-y-4 rounded-xl border border-dashed border-slate-300 bg-slate-50/50 p-8 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200 text-slate-500">
        <Info size={24} aria-hidden="true" />
      </div>
      <div className="space-y-2">
        <h2 className="font-semibold text-slate-900">Analysis Results</h2>
        <p className="mx-auto max-w-xs text-sm text-slate-500">Results will appear here after you submit raw email content.</p>
      </div>
    </div>
  );
}

function LoadingResults() {
  return (
    <section aria-label="Analyzing email" aria-busy="true" className="space-y-5">
      <span className="sr-only">Analyzing email. Results are loading.</span>
      <Card className="border-slate-200 bg-white">
        <CardHeader className="space-y-3">
          <Skeleton className="h-4 w-32 bg-slate-200" />
          <Skeleton className="h-8 w-44 bg-slate-200" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-3 w-full bg-slate-200" />
          <Skeleton className="h-3 w-2/3 bg-slate-200" />
        </CardContent>
      </Card>
      <div className="grid gap-4 sm:grid-cols-2">
        {[0, 1].map((item) => (
          <Card key={item} className="border-slate-200 bg-white p-5">
            <Skeleton className="h-5 w-36 bg-slate-200" />
            <Skeleton className="mt-4 h-4 w-full bg-slate-200" />
            <Skeleton className="mt-2 h-4 w-3/4 bg-slate-200" />
          </Card>
        ))}
      </div>
    </section>
  );
}

export function AnalysisResults({ result, isLoading = false }: { result: UnifiedAnalysisResponse | null; isLoading?: boolean }) {
  if (isLoading) return <LoadingResults />;
  if (!result) return <EmptyResults />;

  const style = classificationStyles[result.decision.classification];
  const ClassificationIcon = style.icon;
  const sender = result.parser.sender
    ? `${result.parser.sender.name ? `${result.parser.sender.name} ` : ''}<${result.parser.sender.address}>`
    : 'Unknown sender';

  return (
    <section aria-live="polite" aria-label="Email analysis results" className="space-y-5">
      <Card className={cn('shadow-sm', style.panel)}>
        <CardHeader className="pb-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <ClassificationIcon className={style.text} size={28} aria-hidden="true" />
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Final classification</p>
                <CardTitle className="mt-1">
                  <Badge variant="outline" className={cn('text-sm capitalize', style.badge)}>{result.decision.classification}</Badge>
                </CardTitle>
              </div>
            </div>
            <div className="flex gap-5 text-right">
              <div><p className="text-xs text-slate-500">Risk score</p><p className="text-xl font-bold text-slate-900">{result.decision.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></p></div>
              <div><p className="text-xs text-slate-500">Confidence</p><p className="text-xl font-bold text-slate-900">{Math.round(result.decision.confidence * 100)}%</p></div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Progress value={result.decision.risk_score} aria-label={`Risk score ${result.decision.risk_score} out of 100`} className={cn('h-2 bg-slate-200', style.progress)} />
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card className="border-slate-200 bg-white">
          <CardHeader className="pb-3"><CardTitle className="text-base text-slate-900">Rule-analysis summary</CardTitle></CardHeader>
          <CardContent className="text-sm text-slate-600">
            <p>{result.rule_analysis.signals.length} signal{result.rule_analysis.signals.length === 1 ? '' : 's'} · score {result.rule_analysis.risk_score}/100</p>
            <div className="mt-2 flex items-center gap-1 text-xs text-slate-500">
              <span>Engine {result.rule_analysis.engine_version}</span>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild><button type="button" aria-label="About the rule engine version" className="rounded text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"><CircleHelp size={14} aria-hidden="true" /></button></TooltipTrigger>
                  <TooltipContent className="border-slate-200 bg-slate-900 text-white">Version of the deterministic detection engine.</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200 bg-white">
          <CardHeader className="pb-3"><CardTitle className="text-base text-slate-900">ML-analysis summary</CardTitle></CardHeader>
          <CardContent>
            <Badge variant="outline" className={result.ml_analysis.status === 'available' ? 'border-green-200 bg-green-100 text-green-800' : 'border-amber-200 bg-amber-100 text-amber-800'}>{result.ml_analysis.status === 'available' ? 'ML available' : 'ML unavailable'}</Badge>
            {result.ml_analysis.status === 'available' ? (
              <p className="mt-2 text-sm text-slate-600"><span className="capitalize">{result.ml_analysis.prediction}</span> · {Math.round((result.ml_analysis.phishing_probability ?? 0) * 100)}% phishing probability</p>
            ) : (
              <p className="mt-2 text-sm text-slate-600">{result.ml_analysis.reason || 'Machine-learning analysis was not used.'}</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-slate-200 bg-white">
        <CardHeader><CardTitle className="text-base text-slate-900">Parsed email summary</CardTitle></CardHeader>
        <CardContent>
          <dl className="grid gap-4 text-sm sm:grid-cols-2">
            <div className="flex gap-2"><Mail size={16} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" /><div><dt className="text-xs text-slate-500">Subject</dt><dd className="break-words text-slate-800">{result.parser.subject || '(No subject)'}</dd></div></div>
            <div className="flex gap-2"><Mail size={16} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" /><div><dt className="text-xs text-slate-500">Sender</dt><dd className="break-all text-slate-800">{sender}</dd></div></div>
            <div className="flex gap-2"><Users size={16} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" /><div><dt className="text-xs text-slate-500">Recipients</dt><dd className="text-slate-800">{result.parser.recipients.length}</dd></div></div>
            <div className="flex gap-2"><Paperclip size={16} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" /><div><dt className="text-xs text-slate-500">Attachments</dt><dd className="text-slate-800">{result.parser.attachments.length}</dd></div></div>
          </dl>
          <Separator className="my-4 bg-slate-200" />
          <div className="flex gap-2">
            <LinkIcon size={16} className="mt-0.5 shrink-0 text-slate-400" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-xs text-slate-500">Extracted URLs ({result.parser.extracted_urls.length})</p>
              {result.parser.extracted_urls.length ? <ul className="mt-1 space-y-1 text-xs text-slate-700">{result.parser.extracted_urls.map((url) => <li key={url} className="break-all">{url}</li>)}</ul> : <p className="text-sm text-slate-600">None detected</p>}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-slate-200 bg-white">
        <CardHeader><CardTitle className="text-base text-slate-900">Threat signals</CardTitle></CardHeader>
        <CardContent>
          {result.rule_analysis.signals.length ? (
            <ul className="space-y-4">
              {result.rule_analysis.signals.map((signal, index) => (
                <li key={signal.code}>
                  {index > 0 && <Separator className="mb-4 bg-slate-200" />}
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0 flex-1"><h4 className="text-sm font-semibold text-slate-900">{signal.title}</h4><p className="mt-1 text-sm text-slate-600">{signal.description}</p></div>
                    <Badge variant="outline" className={cn('capitalize', severityStyles[signal.severity])}>{signal.severity} · +{signal.score}</Badge>
                  </div>
                  <p className="mt-2 text-xs capitalize text-slate-500">Category: {signal.category}</p>
                  {signal.evidence && <p className="mt-1 break-words text-xs text-slate-500">Evidence: {signal.evidence}</p>}
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-600">No deterministic threat signals were detected.</p>}
        </CardContent>
      </Card>

      <Card className="border-blue-100 bg-blue-50/50">
        <CardHeader><CardTitle className="text-base text-slate-900">Recommendations</CardTitle></CardHeader>
        <CardContent><ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">{result.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul></CardContent>
      </Card>
    </section>
  );
}
