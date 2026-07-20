import {
  AlertTriangle,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';

import {
  allSignalValues,
  displayPrediction,
  displayRisk,
  topReasons,
  uniqueSignalValues,
} from '@/lib/production-analysis-ui';
import type { PredictionResponse } from '@/types/inference';

type Tone = 'danger' | 'warning' | 'success';

const toneClasses: Record<Tone, { text: string; border: string; background: string; bar: string }> = {
  danger: { text: 'text-danger', border: 'border-danger/35', background: 'bg-danger/10', bar: 'bg-danger' },
  warning: { text: 'text-warning', border: 'border-warning/35', background: 'bg-warning/10', bar: 'bg-warning' },
  success: { text: 'text-success', border: 'border-success/35', background: 'bg-success/10', bar: 'bg-success' },
};

function SignalList({ title, values }: { title: string; values: string[] }) {
  const unique = uniqueSignalValues(values);
  return (
    <section className="rounded-lg border border-border bg-background/45 p-4" aria-labelledby={`signals-${title.toLowerCase().replaceAll(' ', '-')}`}>
      <div className="flex items-center justify-between gap-3">
        <h3 id={`signals-${title.toLowerCase().replaceAll(' ', '-')}`} className="text-sm font-semibold text-foreground">{title}</h3>
        <span className="text-xs tabular-nums text-muted-foreground">{unique.length}</span>
      </div>
      {unique.length ? (
        <ul className="mt-3 space-y-2">
          {unique.map((value, index) => (
            <li key={`${value}-${index}`} className="flex gap-2 text-sm leading-5 text-muted-foreground">
              <CircleDot className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
              <span>{value.replaceAll('_', ' ')}</span>
            </li>
          ))}
        </ul>
      ) : <p className="mt-3 text-sm text-muted-foreground">No signals returned in this category.</p>}
    </section>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface/80 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{value}</p>
      {detail && <p className="mt-1 text-xs text-muted-foreground">{detail}</p>}
    </div>
  );
}

export function ProductionAnalysisResults({
  result,
  clientRoundTripMs,
  attachmentCount,
}: {
  result: PredictionResponse;
  clientRoundTripMs: number | null;
  attachmentCount: number;
}) {
  const verdict = displayPrediction(result);
  const concern = displayRisk(result.risk_score);
  const tone: Tone = verdict === 'Phishing' ? 'danger' : verdict === 'Suspicious' ? 'warning' : 'success';
  const style = toneClasses[tone];
  const VerdictIcon = tone === 'success' ? ShieldCheck : tone === 'warning' ? AlertTriangle : ShieldAlert;
  const reasons = topReasons(result.signals);
  const detailedSignals = allSignalValues(result.signals);
  const riskScore = Math.max(0, Math.min(100, Math.round(result.risk_score)));
  const timeline = [
    ['Input received', `${attachmentCount} attachment metadata record${attachmentCount === 1 ? '' : 's'}`],
    ['Signals extracted', `${detailedSignals.length} unique indicators returned`],
    ['Model evaluated', `${result.model_id} · ${result.model_version}`],
    ['Decision prepared', `${verdict} · ${riskScore}/100`],
  ];

  return (
    <section className="space-y-5" aria-live="polite" aria-label="Analysis result">
      <div className={`overflow-hidden rounded-xl border bg-surface/90 ${style.border}`}>
        <div className="grid lg:grid-cols-[minmax(0,1fr)_280px]">
          <div className="p-5 sm:p-7">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className={`grid h-11 w-11 shrink-0 place-items-center rounded-lg ${style.background} ${style.text}`}><VerdictIcon aria-hidden="true" /></span>
                <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">Final verdict</p><h2 className={`mt-1 text-3xl font-semibold ${style.text}`}>{verdict}</h2></div>
              </div>
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${style.border} ${style.background} ${style.text}`}>Concern level: {concern}</span>
            </div>

            <div className="mt-6 rounded-lg border border-border bg-background/55 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Recommended action</p>
              <p className="mt-2 text-base font-medium leading-7 text-foreground">{result.recommendations[0] ?? 'No recommended action was returned.'}</p>
            </div>

            <div className="mt-5">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Top reasons</p>
              {reasons.length ? <ul className="mt-3 grid gap-2 sm:grid-cols-3">{reasons.map((reason) => <li key={reason} className="flex gap-2 text-sm leading-5 text-muted-foreground"><CircleDot className={`mt-0.5 h-4 w-4 shrink-0 ${style.text}`} aria-hidden="true" />{reason.replaceAll('_', ' ')}</li>)}</ul> : <p className="mt-2 text-sm text-muted-foreground">No threat signals were returned.</p>}
            </div>
          </div>

          <aside className="border-t border-border bg-background/45 p-5 lg:border-l lg:border-t-0 sm:p-7">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Risk score</p>
            <p className="mt-2 text-5xl font-semibold tabular-nums text-foreground">{riskScore}<span className="text-base font-normal text-muted-foreground">/100</span></p>
            <div className="mt-5 h-2 overflow-hidden rounded-full bg-surface-muted" role="progressbar" aria-label={`Risk score ${riskScore} out of 100`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={riskScore}><div className={`h-full rounded-full ${style.bar}`} style={{ width: `${riskScore}%` }} /></div>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">Automated analysis supports human review and does not guarantee safety.</p>
          </aside>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="Analysis metrics">
        <Metric label="Phishing probability" value={`${(result.probability * 100).toFixed(1)}%`} />
        <Metric label="Confidence" value={`${(result.confidence * 100).toFixed(1)}%`} />
        <Metric label="Model processing time" value={`${result.processing_time_ms.toFixed(1)} ms`} detail="Returned by the model API" />
        <Metric label="Client round-trip" value={clientRoundTripMs === null ? 'Unavailable' : `${clientRoundTripMs.toFixed(0)} ms`} detail="Measured separately in this browser" />
      </div>

      <section className="rounded-xl border border-border bg-surface/80 p-5" aria-labelledby="signal-families-heading">
        <h2 id="signal-families-heading" className="text-base font-semibold text-foreground">Relevant signal families</h2>
        {result.feature_families.length ? <div className="mt-3 flex flex-wrap gap-2">{result.feature_families.map((family) => <span key={family} className="rounded-full border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary">{family.replaceAll('_', ' ')}</span>)}</div> : <p className="mt-2 text-sm text-muted-foreground">No signal families were returned.</p>}
      </section>

      <section className="rounded-xl border border-border bg-surface/80 p-5" aria-labelledby="detailed-indicators-heading">
        <h2 id="detailed-indicators-heading" className="text-base font-semibold text-foreground">Detailed indicators</h2>
        <p className="mt-1 text-sm text-muted-foreground">Only indicators returned by the analysis API are shown.</p>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <SignalList title="Detected indicators" values={result.signals.detected_indicators} />
          <SignalList title="Phishing signals" values={result.signals.phishing_signals} />
          <SignalList title="Urgency indicators" values={result.signals.urgency_indicators} />
          <SignalList title="URL indicators" values={result.signals.url_indicators} />
          <SignalList title="Authentication signals" values={result.signals.authentication_signals} />
        </div>
      </section>

      <section className="rounded-xl border border-border bg-surface/80 p-5" aria-labelledby="analysis-timeline-heading">
        <h2 id="analysis-timeline-heading" className="text-base font-semibold text-foreground">Analysis timeline</h2>
        <ol className="mt-4 grid gap-4 sm:grid-cols-4">{timeline.map(([label, detail]) => <li key={label} className="flex gap-3 sm:block"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-success/40 bg-success/10 text-success"><Check className="h-3.5 w-3.5" aria-hidden="true" /></span><div className="sm:mt-3"><p className="text-sm font-semibold text-foreground">{label}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p></div></li>)}</ol>
      </section>

      <section className="rounded-xl border border-border bg-surface/80 p-5" aria-labelledby="recommendations-heading">
        <h2 id="recommendations-heading" className="text-base font-semibold text-foreground">Recommendations</h2>
        {result.recommendations.length ? <ol className="mt-4 space-y-3">{result.recommendations.map((item, index) => <li key={`${item}-${index}`} className="flex gap-3 text-sm leading-6 text-muted-foreground"><span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-surface-muted text-[10px] font-semibold text-foreground">{index + 1}</span>{item}</li>)}</ol> : <p className="mt-2 text-sm text-muted-foreground">No recommendations were returned.</p>}
      </section>

      <details className="group rounded-xl border border-border bg-surface/80">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 font-semibold text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><span>Technical metadata</span><ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" aria-hidden="true" /></summary>
        <div className="border-t border-border p-5">
          <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
            {[
              ['Model ID', result.model_id],
              ['Model version', result.model_version],
              ['Prediction', result.prediction],
              ['Threshold used', result.threshold_used.toString()],
              ['Model processing', `${result.processing_time_ms.toFixed(1)} ms`],
              ['Attachment handling', `${attachmentCount} metadata-only record${attachmentCount === 1 ? '' : 's'}`],
            ].map(([label, value]) => <div key={label}><dt className="text-muted-foreground">{label}</dt><dd className="mt-1 break-words font-medium text-foreground">{value}</dd></div>)}
          </dl>
          <p className="mt-5 flex gap-2 rounded-lg border border-primary/25 bg-primary/10 p-3 text-sm leading-6 text-primary"><Clock3 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />Attachment contents were not uploaded, opened, previewed, or scanned.</p>
        </div>
      </details>
    </section>
  );
}
