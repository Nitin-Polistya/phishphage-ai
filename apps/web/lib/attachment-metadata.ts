import type { EmailAttachmentMetadata } from '@/types/analysis';

export const MAX_QUICK_ATTACHMENTS = 10;
export const MAX_QUICK_ATTACHMENT_SIZE = 25 * 1024 * 1024;

export const SUSPICIOUS_ATTACHMENT_EXTENSIONS = new Set([
  '.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.iso', '.img', '.zip', '.rar',
  '.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm',
]);

export interface SelectedQuickAttachment {
  key: string;
  lastModified: number;
  metadata: EmailAttachmentMetadata;
}

export interface AttachmentSelectionResult {
  attachments: SelectedQuickAttachment[];
  errors: string[];
}

type FileMetadata = Pick<File, 'name' | 'type' | 'size' | 'lastModified'>;

export function extensionFromFilename(filename: string): string | null {
  const match = filename.trim().toLowerCase().match(/\.[^.]+$/);
  return match?.[0] ?? null;
}

export function attachmentKey(file: FileMetadata): string {
  return `${file.name}\u0000${file.size}\u0000${file.lastModified}`;
}

export function deriveAttachmentMetadata(file: FileMetadata): SelectedQuickAttachment {
  const filename = file.name.trim();
  const extension = extensionFromFilename(filename);
  return {
    key: attachmentKey(file),
    lastModified: file.lastModified,
    metadata: {
      filename,
      content_type: file.type || 'application/octet-stream',
      size_bytes: file.size,
      disposition: 'attachment',
      extension,
      suspicious_extension: extension ? SUSPICIOUS_ATTACHMENT_EXTENSIONS.has(extension) : false,
    },
  };
}

export function mergeAttachmentSelection(
  current: SelectedQuickAttachment[],
  files: Iterable<FileMetadata>,
): AttachmentSelectionResult {
  const attachments = [...current];
  const keys = new Set(current.map((attachment) => attachment.key));
  const errors: string[] = [];

  for (const file of files) {
    if (!file.name.trim()) {
      errors.push('An attachment with an empty filename was rejected.');
      continue;
    }
    if (file.size > MAX_QUICK_ATTACHMENT_SIZE) {
      errors.push(`${file.name} exceeds the 25 MB metadata-only selection limit.`);
      continue;
    }
    const key = attachmentKey(file);
    if (keys.has(key)) {
      errors.push(`${file.name} is already selected.`);
      continue;
    }
    if (attachments.length >= MAX_QUICK_ATTACHMENTS) {
      errors.push(`A maximum of ${MAX_QUICK_ATTACHMENTS} attachments can be selected.`);
      break;
    }
    attachments.push(deriveAttachmentMetadata(file));
    keys.add(key);
  }

  return { attachments, errors };
}

export function removeSelectedAttachment(
  attachments: SelectedQuickAttachment[],
  key: string,
): SelectedQuickAttachment[] {
  return attachments.filter((attachment) => attachment.key !== key);
}

export function clearSelectedAttachments(): SelectedQuickAttachment[] {
  return [];
}

export function toAttachmentMetadataPayload(
  attachments: SelectedQuickAttachment[],
): EmailAttachmentMetadata[] {
  return attachments.map(({ metadata }) => ({ ...metadata }));
}

export function formatFileSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}
