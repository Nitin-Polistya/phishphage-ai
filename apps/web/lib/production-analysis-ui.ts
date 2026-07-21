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

export type IndicatorTone = 'risk' | 'protective' | 'neutral' | 'unknown';

export type IndicatorPresentation = {
  key: string;
  raw: string;
  label: string;
  description: string;
  category: 'Message content' | 'Links and destinations' | 'Email authentication' | 'Urgency and pressure' | 'Other technical indicators';
  tone: IndicatorTone;
  statusLabel: string;
  sourceCategories: string[];
};

type SignalSource = 'detected' | 'phishing' | 'urgency' | 'url' | 'authentication';

const sourceLabels: Record<SignalSource, IndicatorPresentation['category']> = {
  detected: 'Other technical indicators',
  phishing: 'Message content',
  urgency: 'Urgency and pressure',
  url: 'Links and destinations',
  authentication: 'Email authentication',
};

const knownIndicators: Record<string, Pick<IndicatorPresentation, 'label' | 'description'>> = {
  account: {
    label: 'Account-related language',
    description: 'The message contains language about an account, access, verification, or account status.',
  },
  actionable_url: {
    label: 'Link asks the recipient to take action',
    description: 'The message encourages the recipient to open or use a web link.',
  },
  urgent_language: {
    label: 'Urgent or time-pressure language',
    description: 'The message uses urgency or a deadline to encourage a quick response.',
  },
  credential_request: {
    label: 'Credential request',
    description: 'The message refers to passwords, credentials, or signing in.',
  },
  password: {
    label: 'Password-related language',
    description: 'The message contains language related to passwords or account access.',
  },
  login: {
    label: 'Login-related language',
    description: 'The message contains language related to signing in or accessing an account.',
  },
  spf: {
    label: 'SPF authentication record',
    description: 'SPF helps receiving mail systems check whether a server is allowed to send email for a domain.',
  },
  dkim: {
    label: 'DKIM signature',
    description: 'DKIM can help verify that parts of an email were not altered after it was signed.',
  },
  dmarc: {
    label: 'DMARC policy',
    description: 'DMARC tells receiving systems how a domain expects SPF and DKIM results to be handled.',
  },
};

function readableIdentifier(value: string): string {
  return value
    .replaceAll(/([a-z])([A-Z])/g, '$1 $2')
    .replaceAll(/[_-]+/g, ' ')
    .replaceAll(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (character) => character.toUpperCase()) || 'Unspecified indicator';
}

export function normalizeIndicatorKey(value: string): string {
  return value.trim().toLowerCase().replaceAll(/[^a-z0-9]+/g, '_').replaceAll(/^_|_$/g, '');
}

function authenticationStatus(raw: string, key: string): { key: string; label: string; tone: IndicatorTone } {
  const status = raw.toLowerCase().match(/(?:pass(?:ed)?|fail(?:ed)?|missing|unavailable|unknown)/)?.[0];
  if (!['spf', 'dkim', 'dmarc'].includes(key) || !status) return { key, label: 'Detected', tone: 'neutral' };
  if (status.startsWith('pass')) return { key, label: 'Passed', tone: 'protective' };
  if (status.startsWith('fail')) return { key, label: 'Failed', tone: 'risk' };
  if (status === 'missing') return { key, label: 'Not found', tone: 'neutral' };
  return { key, label: 'Status unavailable', tone: 'unknown' };
}

export function presentIndicator(raw: string, source: SignalSource = 'detected'): IndicatorPresentation {
  const normalized = normalizeIndicatorKey(raw);
  const baseKey = normalized.replace(/(?:^|_)(?:passed|pass|failed|fail|missing|unavailable|unknown)$/, '');
  const auth = authenticationStatus(raw, baseKey);
  const known = knownIndicators[baseKey];
  const isAuthentication = ['spf', 'dkim', 'dmarc'].includes(baseKey);
  const tone: IndicatorTone = auth.tone !== 'neutral'
    ? auth.tone
    : isAuthentication || source === 'detected'
      ? 'neutral'
      : 'risk';
  return {
    key: baseKey || normalized,
    raw,
    label: known?.label ?? readableIdentifier(baseKey || normalized),
    description: known?.description ?? 'The analysis service returned this technical indicator; its meaning is not mapped in the interface.',
    category: sourceLabels[source],
    tone,
    statusLabel: isAuthentication ? auth.label : tone === 'risk' ? 'Potential concern' : 'Neutral technical finding',
    sourceCategories: [sourceLabels[source]],
  };
}

const sourceValues: Array<[SignalSource, keyof InferenceSignals]> = [
  ['phishing', 'phishing_signals'],
  ['urgency', 'urgency_indicators'],
  ['url', 'url_indicators'],
  ['authentication', 'authentication_signals'],
  ['detected', 'detected_indicators'],
];

export function uniqueIndicatorPresentations(signals: InferenceSignals): IndicatorPresentation[] {
  const findings = new Map<string, IndicatorPresentation>();
  for (const [source, field] of sourceValues) {
    for (const raw of signals[field]) {
      if (!raw?.trim()) continue;
      const presentation = presentIndicator(raw, source);
      const existing = findings.get(presentation.key);
      if (existing) {
        existing.sourceCategories = [...new Set([...existing.sourceCategories, presentation.category])];
        if (presentation.tone !== 'neutral' && existing.tone === 'neutral') {
          existing.tone = presentation.tone;
          existing.statusLabel = presentation.statusLabel;
          existing.category = presentation.category;
        }
      } else {
        findings.set(presentation.key, presentation);
      }
    }
  }
  return [...findings.values()];
}

export function explainabilitySummary(signals: InferenceSignals, limit = 5): string[] {
  const findings = uniqueIndicatorPresentations(signals);
  return findings.slice(0, limit).map((finding) => {
    if (finding.category === 'Email authentication') return `${finding.label} was referenced in the analyzed source (${finding.statusLabel.toLowerCase()}).`;
    return `${finding.label} was identified.`;
  });
}

export function findingCountLabel(count: number, noun = 'unique finding'): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
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
