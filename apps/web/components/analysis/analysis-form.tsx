"use client";

import { useState } from 'react';
import { MOCK_EXAMPLE_EMAIL } from '@/lib/mock-data';
import { analyzeRawEmail, ApiError } from '@/lib/api';
import type { UnifiedAnalysisResponse } from '@/types/analysis';
import { Loader2, Trash2, Send } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { AnalysisResults } from './analysis-results';

export function AnalysisForm() {
  const [emailContent, setEmailContent] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UnifiedAnalysisResponse | null>(null);

  const handleExample = () => {
    setEmailContent(MOCK_EXAMPLE_EMAIL);
    setError(null);
    setResult(null);
  };

  const handleClear = () => {
    setEmailContent('');
    setError(null);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!emailContent.trim()) {
      setError('Please provide email content to analyze.');
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      setResult(await analyzeRawEmail(emailContent));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError ? caught.message : 'Unexpected analysis error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="grid gap-8 lg:grid-cols-12">
      <div className="space-y-6 lg:col-span-6">
      <div className="flex flex-col gap-2">
        <label htmlFor="email-content" className="text-sm font-medium text-slate-700">
          Raw Email Content
        </label>
        <Textarea
          id="email-content"
          className="min-h-[400px] resize-y rounded-xl border-slate-200 bg-white p-4 font-mono text-sm text-slate-700 placeholder:text-slate-400 focus-visible:border-blue-500 focus-visible:ring-blue-500/20"
          placeholder="Paste the raw email source here (including headers)..."
          value={emailContent}
          onChange={(e) => setEmailContent(e.target.value)}
          aria-describedby={error ? 'analysis-error' : undefined}
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleExample}
            disabled={isLoading}
            className="text-xs text-slate-600 hover:bg-slate-100 hover:text-slate-900"
          >
            Load Example
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleClear}
            disabled={isLoading}
            className="text-xs text-red-600 hover:bg-red-50 hover:text-red-700"
          >
            <Trash2 aria-hidden="true" />
            Clear
          </Button>
        </div>

        <Button
          type="button"
          onClick={handleAnalyze}
          disabled={isLoading || !emailContent.trim()}
          className="bg-blue-600 px-6 font-semibold text-white shadow-sm hover:bg-blue-700"
        >
          {isLoading ? (
            <>
              <Loader2 className="animate-spin" aria-hidden="true" />
              Analyzing...
            </>
          ) : (
            <>
              <Send aria-hidden="true" />
              Analyze Email
            </>
          )}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive" className="border-red-200 bg-red-50 text-red-800">
          <div className="flex items-center justify-between gap-3">
            <div>
              <AlertTitle>Analysis failed</AlertTitle>
              <AlertDescription id="analysis-error">{error}</AlertDescription>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={handleAnalyze} disabled={isLoading || !emailContent.trim()} className="shrink-0 border-red-200 bg-white text-red-700 hover:bg-red-100 hover:text-red-800">
              Retry
            </Button>
          </div>
        </Alert>
      )}
      </div>
      <div className="lg:col-span-6">
        <AnalysisResults result={result} isLoading={isLoading} />
      </div>
    </div>
  );
}
