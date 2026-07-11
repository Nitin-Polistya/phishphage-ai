import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Link as LinkIcon,
  Mail,
  Paperclip,
  ShieldAlert,
  Users,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import type { ThreatClassification, UnifiedAnalysisResponse } from '@/types/analysis';

const classificationStyles: Record<ThreatClassification, { panel: string; text: string; icon: typeof CheckCircle2 }> = {
  safe: { panel: 'border-green-200 bg-green-50', text: 'text-green-700', icon: CheckCircle2 },
  suspicious: { panel: 'border-amber-200 bg-amber-50', text: 'text-amber-700', icon: AlertTriangle },
  phishing: { panel: 'border-red-200 bg-red-50', text: 'text-red-700', icon: ShieldAlert },
};

function EmptyResults() {
  return (
    <div className="flex h-full min-h-[420px] flex-col items-center justify-center space-y-4 rounded-xl border border-dashed border-slate-300 bg-slate-50/50 p-8 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200 text-slate-500">
        <Info size={24} />
      </div>
      <div className="space-y-2">
        <h2 className="font-semibold text-slate-900">Analysis Results</h2>
        <p className="mx-auto max-w-xs text-sm text-slate-500">
          Results will appear here after you submit raw email content.
        </p>
      </div>
    </div>
  );
}

export function AnalysisResults({ result }: { result: UnifiedAnalysisResponse | null }) {
  if (!result) return <EmptyResults />;

  const style = classificationStyles[result.decision.classification];
  const ClassificationIcon = style.icon;
  const sender = result.parser.sender
    ? `${result.parser.sender.name ? `${result.parser.sender.name} ` : ''}<${result.parser.sender.address}>`
    : 'Unknown sender';

  return (
    <section aria-live="polite" aria-label="Email analysis results" className="space-y-5">
      <div className={cn('rounded-xl border p-5', style.panel)}>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <ClassificationIcon className={style.text} size={28} aria-hidden="true" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Final classification</p>
              <h2 className={cn('text-2xl font-bold capitalize', style.text)}>{result.decision.classification}</h2>
            </div>
          </div>
          <div className="flex gap-5 text-right">
            <div>
              <p className="text-xs text-slate-500">Risk score</p>
              <p className="text-xl font-bold text-slate-900">{result.decision.risk_score}<span className="text-sm font-normal text-slate-500">/100</span></p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Confidence</p>
              <p className="text-xl font-bold text-slate-900">{Math.round(result.decision.confidence * 100)}%</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h3 className="font-semibold text-slate-900">Machine learning</h3>
          <p className={cn('mt-2 text-sm font-semibold capitalize', result.ml_analysis.status === 'available' ? 'text-green-700' : 'text-amber-700')}>
            {result.ml_analysis.status}
          </p>
          {result.ml_analysis.status === 'available' ? (
            <p className="mt-1 text-sm text-slate-600">
              {result.ml_analysis.prediction} · {Math.round((result.ml_analysis.phishing_probability ?? 0) * 100)}% phishing probability
            </p>
          ) : (
            <p className="mt-1 text-sm text-slate-600">{result.ml_analysis.reason || 'Machine-learning analysis was not used.'}</p>
          )}
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <h3 className="font-semibold text-slate-900">Rule analysis</h3>
          <p className="mt-2 text-sm text-slate-600">
            {result.rule_analysis.signals.length} signal{result.rule_analysis.signals.length === 1 ? '' : 's'} · score {result.rule_analysis.risk_score}/100
          </p>
          <p className="mt-1 text-xs text-slate-500">Engine {result.rule_analysis.engine_version}</p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5">
        <h3 className="font-semibold text-slate-900">Parsed email summary</h3>
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
          <div className="flex gap-2"><Mail size={16} className="mt-0.5 shrink-0 text-slate-400" /><div><dt className="text-xs text-slate-500">Subject</dt><dd className="break-words text-slate-800">{result.parser.subject || '(No subject)'}</dd></div></div>
          <div className="flex gap-2"><Mail size={16} className="mt-0.5 shrink-0 text-slate-400" /><div><dt className="text-xs text-slate-500">Sender</dt><dd className="break-all text-slate-800">{sender}</dd></div></div>
          <div className="flex gap-2"><Users size={16} className="mt-0.5 shrink-0 text-slate-400" /><div><dt className="text-xs text-slate-500">Recipients</dt><dd className="text-slate-800">{result.parser.recipients.length}</dd></div></div>
          <div className="flex gap-2"><Paperclip size={16} className="mt-0.5 shrink-0 text-slate-400" /><div><dt className="text-xs text-slate-500">Attachments</dt><dd className="text-slate-800">{result.parser.attachments.length}</dd></div></div>
        </dl>
        <div className="mt-4 flex gap-2">
          <LinkIcon size={16} className="mt-0.5 shrink-0 text-slate-400" />
          <div className="min-w-0">
            <p className="text-xs text-slate-500">Extracted URLs ({result.parser.extracted_urls.length})</p>
            {result.parser.extracted_urls.length ? (
              <ul className="mt-1 space-y-1 text-xs text-slate-700">
                {result.parser.extracted_urls.map((url) => <li key={url} className="break-all">{url}</li>)}
              </ul>
            ) : <p className="text-sm text-slate-600">None detected</p>}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5">
        <h3 className="font-semibold text-slate-900">Threat signals</h3>
        {result.rule_analysis.signals.length ? (
          <ul className="mt-4 space-y-3">
            {result.rule_analysis.signals.map((signal) => (
              <li key={signal.code} className="rounded-lg border border-slate-200 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div><h4 className="text-sm font-semibold text-slate-900">{signal.title}</h4><p className="mt-1 text-sm text-slate-600">{signal.description}</p></div>
                  <span className="rounded-full bg-slate-100 px-2 py-1 text-xs font-medium capitalize text-slate-700">{signal.severity} · +{signal.score}</span>
                </div>
                <p className="mt-2 text-xs capitalize text-slate-500">Category: {signal.category}</p>
                {signal.evidence && <p className="mt-1 break-words text-xs text-slate-500">Evidence: {signal.evidence}</p>}
              </li>
            ))}
          </ul>
        ) : <p className="mt-3 text-sm text-slate-600">No deterministic threat signals were detected.</p>}
      </div>

      <div className="rounded-xl border border-blue-100 bg-blue-50/50 p-5">
        <h3 className="font-semibold text-slate-900">Recommendations</h3>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-700">
          {result.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}
        </ul>
      </div>
    </section>
  );
}
