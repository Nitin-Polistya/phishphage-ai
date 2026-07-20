import type { EmailAttachmentMetadata } from '@/types/analysis';
import type { InferenceSignals, PredictionResponse } from '@/types/inference';

export type QuickPasteFields = {
  senderName: string;
  senderEmail: string;
  recipientName: string;
  recipientEmail: string;
  replyTo: string;
  subject: string;
  body: string;
};

export type QuickPasteField = keyof QuickPasteFields;
export type QuickPasteValidationError = { field: QuickPasteField; message: string };

export type RequestTimingState = {
  sequence: number;
  modelProcessingMs: number | null;
  clientRoundTripMs: number | null;
};

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const emptyQuickPaste: QuickPasteFields = {
  senderName: '',
  senderEmail: '',
  recipientName: '',
  recipientEmail: '',
  replyTo: '',
  subject: '',
  body: '',
};

export function isValidEmailAddress(value: string): boolean {
  return emailPattern.test(value.trim());
}

export function validateQuickPaste(fields: QuickPasteFields): QuickPasteValidationError | null {
  const emailFields: Array<[QuickPasteField, string]> = [
    ['senderEmail', 'Sender email'],
    ['recipientEmail', 'Recipient email'],
    ['replyTo', 'Reply-To'],
  ];
  for (const [field, label] of emailFields) {
    const value = fields[field].trim();
    if (value && !isValidEmailAddress(value)) return { field, message: `${label} must be a valid email address.` };
  }
  if (!fields.subject.trim() && !fields.body.trim()) {
    return { field: 'body', message: 'Subject or body must contain content.' };
  }
  return null;
}

export function buildQuickPasteRawEmail(fields: QuickPasteFields, attachments: EmailAttachmentMetadata[] = []): string {
  const headers: string[] = [];
  const senderName = fields.senderName.trim();
  const senderEmail = fields.senderEmail.trim();
  const recipientName = fields.recipientName.trim();
  const recipientEmail = fields.recipientEmail.trim();
  const replyTo = fields.replyTo.trim();
  const subject = fields.subject.trim();
  if (senderName || senderEmail) headers.push(`From: ${senderName ? `${senderName} ` : ''}${senderEmail ? `<${senderEmail}>` : ''}`.trim());
  if (recipientName || recipientEmail) headers.push(`To: ${recipientName ? `${recipientName} ` : ''}${recipientEmail ? `<${recipientEmail}>` : ''}`.trim());
  if (replyTo) headers.push(`Reply-To: ${replyTo}`);
  if (subject) headers.push(`Subject: ${subject}`);
  headers.push('MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8');
  const metadata = attachments
    .filter((item) => item.filename?.trim())
    .map((item) => `Attachment metadata: ${item.filename?.trim()}${item.content_type ? ` (${item.content_type})` : ''}, ${item.size_bytes} bytes`);
  return `${headers.join('\n')}\n\n${[fields.body.trim(), ...metadata].filter(Boolean).join('\n')}`;
}

export function displayRisk(score: number): 'Low' | 'Moderate' | 'High' | 'Critical' {
  if (score >= 85) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Moderate';
  return 'Low';
}

export function displayPrediction(result: Pick<PredictionResponse, 'prediction' | 'probability'>): string {
  if (result.prediction === 'phishing') return 'Phishing';
  return result.probability >= 0.35 ? 'Suspicious' : 'Low risk';
}

export function uniqueSignalValues(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function allSignalValues(signals: InferenceSignals): string[] {
  return uniqueSignalValues([
    ...signals.detected_indicators,
    ...signals.phishing_signals,
    ...signals.urgency_indicators,
    ...signals.authentication_signals,
    ...signals.url_indicators,
  ]);
}

export function topReasons(signals: InferenceSignals, limit = 3): string[] {
  return allSignalValues(signals).slice(0, limit);
}

export function beginRequest(previousSequence: number): RequestTimingState {
  return { sequence: previousSequence + 1, modelProcessingMs: null, clientRoundTripMs: null };
}

export function completeRequestTiming(
  state: RequestTimingState,
  responseSequence: number,
  processingTimeMs: number,
  clientRoundTripMs: number,
): RequestTimingState {
  if (state.sequence !== responseSequence) return state;
  return { ...state, modelProcessingMs: processingTimeMs, clientRoundTripMs };
}

export function clearRequestTiming(state: RequestTimingState, responseSequence: number): RequestTimingState {
  if (state.sequence !== responseSequence) return state;
  return { ...state, modelProcessingMs: null, clientRoundTripMs: null };
}

export function isCurrentRequest(activeSequence: number, responseSequence: number): boolean {
  return activeSequence === responseSequence;
}
