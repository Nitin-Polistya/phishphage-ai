"use client";

import { useState } from 'react';
import { MOCK_EXAMPLE_EMAIL } from '@/lib/mock-data';
import { cn } from '@/lib/utils';
import { analyzeRawEmail, ApiError } from '@/lib/api';
import type { UnifiedAnalysisResponse } from '@/types/analysis';
import { Loader2, Trash2, Send } from 'lucide-react';
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
        <textarea
          id="email-content"
          className="min-h-[400px] w-full rounded-xl border border-slate-200 bg-white p-4 text-sm font-mono text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all resize-none"
          placeholder="Paste the raw email source here (including headers)..."
          value={emailContent}
          onChange={(e) => setEmailContent(e.target.value)}
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button 
            onClick={handleExample}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-100 rounded-md transition-colors"
          >
            Load Example
          </button>
          <button 
            onClick={handleClear}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-red-600 hover:bg-red-50 rounded-md transition-colors"
          >
            <Trash2 size={14} />
            Clear
          </button>
        </div>

        <button 
          onClick={handleAnalyze}
          disabled={isLoading || !emailContent.trim()}
          className={cn(
            "flex items-center gap-2 px-6 py-2 rounded-md text-sm font-semibold text-white transition-all",
            isLoading || !emailContent.trim()
              ? "bg-blue-400 cursor-not-allowed" 
              : "bg-blue-600 hover:bg-blue-700 shadow-sm hover:shadow-md"
          )}
        >
          {isLoading ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Send size={16} />
              Analyze Email
            </>
          )}
        </button>
      </div>

      {error && (
        <div role="alert" className="flex items-center justify-between gap-3 rounded-md border border-red-100 bg-red-50 p-3 text-xs font-medium text-red-700">
          <span>{error}</span>
          <button type="button" onClick={handleAnalyze} className="shrink-0 rounded border border-red-200 bg-white px-3 py-1.5 hover:bg-red-50">Retry</button>
        </div>
      )}
      </div>
      <div className="lg:col-span-6">
        <AnalysisResults result={result} />
      </div>
    </div>
  );
}
