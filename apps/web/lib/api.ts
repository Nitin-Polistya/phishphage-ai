import type { AnalysisRequest, UnifiedAnalysisResponse } from '@/types/analysis';
import type { HealthResponse, PredictionResponse } from '@/types/inference';
export type { HealthResponse } from '@/types/inference';

export type ApiErrorKind = 'validation' | 'backend_unavailable' | 'service_unavailable' | 'timeout' | 'cancelled' | 'unexpected';

export class ApiError extends Error {
  constructor(public readonly kind: ApiErrorKind, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export function validateApiBaseUrl(url = API_BASE_URL): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function safeDetail(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object' || !('detail' in payload)) return null;
  const detail = (payload as { detail?: unknown }).detail;
  if (detail && typeof detail === 'object' && !Array.isArray(detail) && 'message' in detail) {
    const message = (detail as { message?: unknown }).message;
    return typeof message === 'string' && message.length <= 300 ? message : null;
  }
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

function requestSignal(signal?: AbortSignal, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort('timeout'), timeoutMs);
  const abort = () => controller.abort(signal?.reason ?? 'cancelled');
  signal?.addEventListener('abort', abort, { once: true });
  return { signal: controller.signal, cleanup: () => { globalThis.clearTimeout(timeout); signal?.removeEventListener('abort', abort); } };
}

export async function analyzeProductionEmail(rawEmail: string, signal?: AbortSignal): Promise<PredictionResponse> {
  const request = requestSignal(signal);
  try {
    let response: Response;
    try {
      response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: rawEmail }), signal: request.signal,
      });
    } catch {
      if (request.signal.aborted) {
        throw new ApiError(signal?.aborted ? 'cancelled' : 'timeout', signal?.aborted ? 'Analysis cancelled.' : 'The analysis request timed out. Try again.');
      }
      throw new ApiError('backend_unavailable', 'Cannot connect to the analysis service. Check that the backend is running and try again.');
    }
    if (!response.ok) {
      const payload: unknown = await response.json().catch(() => null);
      const detail = safeDetail(payload);
      if (response.status === 400 || response.status === 422) throw new ApiError('validation', detail || 'The email content could not be validated.');
      if (response.status === 503) throw new ApiError('service_unavailable', detail || 'The inference model is temporarily unavailable.');
      throw new ApiError('unexpected', 'The analysis service returned an unexpected error. Please try again.');
    }
    const payload: unknown = await response.json();
    if (!payload || typeof payload !== 'object' || typeof (payload as PredictionResponse).model_id !== 'string') {
      throw new ApiError('unexpected', 'The analysis service returned an invalid response.');
    }
    return payload as PredictionResponse;
  } finally {
    request.cleanup();
  }
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

export async function fetchHealthStatus(signal?: AbortSignal): Promise<HealthResponse> {
  if (!validateApiBaseUrl()) {
    throw new ApiError('validation', 'The configured backend API URL is invalid.');
  }

  const request = requestSignal(signal, 5000);
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: request.signal,
    });
    if (!response.ok) throw new ApiError('unexpected', `Health check returned HTTP ${response.status}.`);
    const payload: unknown = await response.json();
    if (!payload || typeof payload !== 'object') throw new ApiError('unexpected', 'The health endpoint returned an invalid response.');
    const health = payload as Partial<HealthResponse>;
    if (typeof health.status !== 'string' || typeof health.service !== 'string' || typeof health.firebase !== 'string') {
      throw new ApiError('unexpected', 'The health endpoint returned an invalid response.');
    }
    return health as HealthResponse;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (request.signal.aborted) throw new ApiError(signal?.aborted ? 'cancelled' : 'timeout', 'The backend health check timed out.');
    throw new ApiError('backend_unavailable', 'The backend health endpoint could not be reached.');
  } finally {
    request.cleanup();
  }
}

export function analyzeRawEmail(rawEmail: string): Promise<UnifiedAnalysisResponse> {
  return analyzeEmail({ input_mode: 'raw_email', raw_email: rawEmail });
}
