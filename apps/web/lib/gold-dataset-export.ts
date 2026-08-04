import type { GoldDatasetExportFile } from '@/types/dataset-review';

const SAFE_OUTPUT_LOCATION = /^services\/ml\/evaluation\/private\/[A-Za-z0-9._/-]+\/$/;
const SAFE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function safeGoldExportLocation(value: string): string {
  if (SAFE_OUTPUT_LOCATION.test(value) && !value.includes('..')) return value;
  return 'private review directory';
}

export function safeGoldExportFilename(value: string): string {
  return SAFE_FILENAME.test(value) ? value : 'unavailable filename';
}

export function safeGoldExportFiles(files: GoldDatasetExportFile[]): GoldDatasetExportFile[] {
  return files.map((file) => ({
    ...file,
    filename: safeGoldExportFilename(file.filename),
  }));
}

export function formatGoldExportError(error: unknown): string {
  const candidate = error as { code?: unknown; kind?: unknown; message?: unknown };
  switch (candidate.code) {
    case 'authorization_failed':
      return 'Export authorization failed. Check the local administrative token.';
    case 'no_approved_records':
      return 'No approved human-reviewed records are available to export.';
    case 'export_storage_failure':
      return 'Export storage failed. The local backend could not write all required files.';
    case 'export_file_verification_failed':
      return 'Export verification failed. One or more required files are missing or unsafe.';
    default:
      if (candidate.kind === 'backend_unavailable') return 'The local dataset-review backend is unavailable.';
      return typeof candidate.message === 'string' && candidate.message
        ? candidate.message
        : 'The approved gold-dataset export failed safely.';
  }
}
