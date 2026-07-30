export const DEFAULT_DATASET_REVIEW_API_BASE_URL = 'http://127.0.0.1:8000';

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

export async function requestDatasetReviewStatus(
  fetcher: typeof fetch,
  apiBaseUrl: string,
): Promise<DatasetReviewStatusResponse> {
  let response: Response;
  try {
    response = await fetcher(`${apiBaseUrl}/api/v1/dataset-review/status`, {
      method: 'GET',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new DatasetReviewStatusError('backend_unavailable', 'Unable to reach dataset review service.');
  }

  if (!response.ok) {
    throw new DatasetReviewStatusError('backend_unavailable', 'Unable to reach dataset review service.');
  }

  const payload: unknown = await response.json().catch(() => null);
  return parseDatasetReviewStatus(payload);
}
