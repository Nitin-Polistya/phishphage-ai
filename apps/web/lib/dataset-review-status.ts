export const DEFAULT_DATASET_REVIEW_API_BASE_URL = 'http://127.0.0.1:8000';
export const DATASET_REVIEW_STATUS_TIMEOUT_MS = 10_000;

export interface DatasetReviewStatusResponse {
  enabled: boolean;
  local_only: boolean;
  gemini_enabled: boolean;
  configured: boolean;
  provider_ready: boolean;
  model_name: string | null;
  prompt_version: string;
  session_limit: number;
  daily_limit: number;
  batch_enabled: boolean;
  storage: string;
  notice: string;
}

export type DatasetReviewStatusErrorKind = 'backend_unavailable' | 'unexpected';

export class DatasetReviewStatusError extends Error {
  readonly kind: DatasetReviewStatusErrorKind;

  constructor(kind: DatasetReviewStatusErrorKind, message: string) {
    super(message);
    this.name = 'DatasetReviewStatusError';
    this.kind = kind;
  }
}

export type DatasetReviewServiceState =
  | { kind: 'loading' }
  | { kind: 'enabled'; status: DatasetReviewStatusResponse }
  | { kind: 'disabled'; status: DatasetReviewStatusResponse }
  | { kind: 'unavailable'; message: string };

export function resolveDatasetReviewApiBaseUrl(configured: string | undefined): string {
  return (configured?.trim() || DEFAULT_DATASET_REVIEW_API_BASE_URL).replace(/\/$/, '');
}

export function isDatasetReviewStatusResponse(payload: unknown): payload is DatasetReviewStatusResponse {
  if (!payload || typeof payload !== 'object') return false;
  const candidate = payload as Record<string, unknown>;
  const booleanFields = ['enabled', 'local_only', 'gemini_enabled', 'configured', 'provider_ready', 'batch_enabled'];
  const numericFields = ['session_limit', 'daily_limit'];
  const stringFields = ['prompt_version', 'storage', 'notice'];
  return booleanFields.every((field) => typeof candidate[field] === 'boolean')
    && numericFields.every((field) => typeof candidate[field] === 'number' && Number.isFinite(candidate[field]))
    && stringFields.every((field) => typeof candidate[field] === 'string')
    && (candidate.model_name === null || typeof candidate.model_name === 'string');
}

export function parseDatasetReviewStatus(payload: unknown): DatasetReviewStatusResponse {
  if (!isDatasetReviewStatusResponse(payload)) {
    throw new DatasetReviewStatusError('unexpected', 'Dataset review service returned an invalid status response.');
  }
  return payload;
}

export function toDatasetReviewServiceState(status: DatasetReviewStatusResponse): DatasetReviewServiceState {
  return status.enabled ? { kind: 'enabled', status } : { kind: 'disabled', status };
}

export async function requestDatasetReviewStatus(
  fetcher: typeof fetch,
  apiBaseUrl: string,
  signal?: AbortSignal,
  timeoutMs = DATASET_REVIEW_STATUS_TIMEOUT_MS,
): Promise<DatasetReviewStatusResponse> {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort('timeout'), timeoutMs);
  const abort = () => controller.abort(signal?.reason ?? 'cancelled');
  signal?.addEventListener('abort', abort, { once: true });
  let response: Response;
  try {
    response = await fetcher(`${apiBaseUrl}/api/v1/dataset-review/status`, {
      method: 'GET',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new DatasetReviewStatusError('backend_unavailable', 'Unable to reach dataset review service.');
    }

    const payload: unknown = await response.json().catch(() => null);
    return parseDatasetReviewStatus(payload);
  } catch (error) {
    if (error instanceof DatasetReviewStatusError) throw error;
    if (controller.signal.reason === 'timeout') {
      throw new DatasetReviewStatusError('backend_unavailable', 'Dataset review service did not respond in time.');
    }
    throw new DatasetReviewStatusError('backend_unavailable', 'Unable to reach dataset review service.');
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}
