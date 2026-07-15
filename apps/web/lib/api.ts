import type { AnalysisRequest, UnifiedAnalysisResponse } from '@/types/analysis';

export type ApiErrorKind = 'validation' | 'backend_unavailable' | 'service_unavailable' | 'unexpected';

export class ApiError extends Error {
  constructor(public readonly kind: ApiErrorKind, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

function safeDetail(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object' || !('detail' in payload)) return null;
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === 'string' && detail.length <= 300) return detail;
  if (Array.isArray(detail)) {
    const messages = detail.flatMap((item) => {
      if (!item || typeof item !== 'object') return [];
      const error = item as { loc?: unknown; msg?: unknown };
      if (typeof error.msg !== 'string') return [];
      const location = Array.isArray(error.loc) ? error.loc.at(-1) : null;
      const field = typeof location === 'string' ? location.replaceAll('_', ' ') : 'input';
      return [`${field}: ${error.msg.replace(/^Value error,\s*/i, '')}`];
    });
    return messages.length ? messages.join(' ') : null;
  }
  return null;
}

export async function analyzeEmail(payload: AnalysisRequest): Promise<UnifiedAnalysisResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/analysis/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new ApiError('backend_unavailable', 'Cannot connect to the analysis service. Check that the backend is running and try again.');
  }

  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail = safeDetail(payload);
    if (response.status === 400 || response.status === 422) {
      throw new ApiError('validation', detail || 'The email content could not be validated.');
    }
    if (response.status === 503) {
      throw new ApiError('service_unavailable', detail || 'The analysis service is temporarily unavailable.');
    }
    throw new ApiError('unexpected', 'The analysis service returned an unexpected error. Please try again.');
  }

  try {
    return (await response.json()) as UnifiedAnalysisResponse;
  } catch {
    throw new ApiError('unexpected', 'The analysis service returned an invalid response.');
  }
}

export function analyzeRawEmail(rawEmail: string): Promise<UnifiedAnalysisResponse> {
  return analyzeEmail({ input_mode: 'raw_email', raw_email: rawEmail });
}
