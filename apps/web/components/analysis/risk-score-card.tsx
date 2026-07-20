import { ShieldAlert, ShieldCheck } from 'lucide-react';

import type { PredictionResponse } from '@/types/inference';

function riskLabel(score: number) {
  if (score >= 85) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Moderate';
  return 'Low';
}

export function RiskScoreCard({ result }: { result: PredictionResponse }) {
  const score = Math.max(0, Math.min(100, Math.round(result.risk_score)));
  const phishing = result.prediction === 'phishing';
  const suspicious = !phishing && result.probability >= 0.35;
  const tone = phishing ? 'rose' : suspicious ? 'amber' : 'emerald';
  const toneClasses = { rose: { text: 'text-rose-300', bar: 'bg-rose-400' }, amber: { text: 'text-amber-300', bar: 'bg-amber-400' }, emerald: { text: 'text-emerald-300', bar: 'bg-emerald-400' } }[tone];
  const label = phishing ? 'Phishing' : suspicious ? 'Suspicious' : 'Low risk';
  const Icon = phishing || suspicious ? ShieldAlert : ShieldCheck;

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/55 p-5" aria-labelledby="risk-score-heading">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Assessment</p>
          <h2 id="risk-score-heading" className={`mt-2 flex items-center gap-2 text-2xl font-semibold ${toneClasses.text}`}>
            <Icon className="h-5 w-5" aria-hidden="true" />{label}
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">Automated analysis supports human judgment; it cannot guarantee that a message is safe.</p>
        </div>
        <div className="text-right">
          <p className="text-xs uppercase tracking-[0.14em] text-slate-500">Risk score</p>
          <p className="mt-1 text-4xl font-semibold tabular-nums text-slate-100">{score}<span className="text-base text-slate-500">/100</span></p>
        </div>
      </div>
      <div className="mt-6">
        <div className="h-2 overflow-hidden rounded-full bg-slate-800" role="progressbar" aria-label={`Risk score ${score} out of 100`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}>
          <div className={`h-full rounded-full ${toneClasses.bar} transition-[width]`} style={{ width: `${score}%` }} />
        </div>
        <div className="mt-2 flex justify-between text-[11px] text-slate-500"><span>Low</span><span>Moderate</span><span>High</span><span>Critical</span></div>
        <p className="sr-only">Risk level: {riskLabel(score)}.</p>
      </div>
    </section>
  );
}
