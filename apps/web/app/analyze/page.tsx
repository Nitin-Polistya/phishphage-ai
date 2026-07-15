import { AnalysisForm } from '@/components/analysis/analysis-form';

export default function AnalyzePage() {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-400">PhishPhage AI investigation workspace</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">Analyze Email</h1>
        <p className="max-w-2xl text-sm leading-6 text-slate-400">Inspect copied email content, complete message source, or an .eml file without storing the submission.</p>
      </div>

      <AnalysisForm />
    </div>
  );
}
