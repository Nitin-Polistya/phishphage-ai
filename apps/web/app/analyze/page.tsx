import { AnalysisForm } from '@/components/analysis/analysis-form';

export default function AnalyzePage() {
  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold tracking-tight text-slate-900">Analyze Email</h1>
        <p className="text-slate-500">Paste raw email source to detect phishing attempts and malicious links.</p>
      </div>

      <AnalysisForm />
    </div>
  );
}
