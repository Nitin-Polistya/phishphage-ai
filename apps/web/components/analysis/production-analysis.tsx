'use client';

import {
  type ChangeEvent,
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  Check,
  CheckCircle2,
  ClipboardPaste,
  FileText,
  Loader2,
  Mail,
  Paperclip,
  RotateCcw,
  Upload,
  X,
} from 'lucide-react';

import { ApiError, analyzeProductionEmail } from '@/lib/api';
import {
  clearSelectedAttachments,
  formatFileSize,
  mergeAttachmentSelection,
  removeSelectedAttachment,
  toAttachmentMetadataPayload,
  type SelectedQuickAttachment,
} from '@/lib/attachment-metadata';
import { EXAMPLE_EMAIL } from '@/lib/example-email';
import { readPreferences } from '@/lib/preferences';
import {
  beginRequest,
  buildQuickPasteRawEmail,
  clearRequestTiming,
  completeRequestTiming,
  emptyQuickPaste,
  isCurrentRequest,
  validateQuickPaste,
  type QuickPasteField,
  type QuickPasteFields,
  type RequestTimingState,
} from '@/lib/production-analysis-ui';
import { createProductionScanRecord, saveScan } from '@/lib/scan-store';
import type { AnalysisInputMode } from '@/types/analysis';
import type { PredictionResponse } from '@/types/inference';
import { BackendStatus } from './backend-status';
import { ProductionAnalysisResults } from './production-analysis-results';

const MAX_EMAIL_BYTES = 2_000_000;
const stages = ['Validating email', 'Parsing headers and content', 'Extracting security indicators', 'Running ML inference', 'Preparing explanation'];
const modes = [
  { id: 'quick_paste' as const, label: 'Quick Paste', actionLabel: 'Analyze Quick Paste', icon: Mail },
  { id: 'raw_email' as const, label: 'Raw Source', actionLabel: 'Analyze Raw Source', icon: FileText },
  { id: 'eml_upload' as const, label: 'Upload .eml', actionLabel: 'Analyze Uploaded .eml', icon: Upload },
];

type ErrorField = QuickPasteField | 'rawSource' | 'emlFile' | 'quickAttachments';
type AnalysisError = { message: string; field?: ErrorField };

function extensionLabel(filename: string | null, contentType: string | null) {
  const extension = filename?.match(/\.[^.]+$/)?.[0]?.toLowerCase();
  return contentType && contentType !== 'application/octet-stream' ? contentType : extension || 'Unknown type';
}

export function ProductionAnalysis() {
  const [mode, setMode] = useState<AnalysisInputMode>('quick_paste');
  const [quick, setQuick] = useState<QuickPasteFields>(emptyQuickPaste);
  const [attachments, setAttachments] = useState<SelectedQuickAttachment[]>([]);
  const [rawSource, setRawSource] = useState('');
  const [selectedFile, setSelectedFile] = useState<{ name: string; size: number } | null>(null);
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [resultAttachmentCount, setResultAttachmentCount] = useState(0);
  const [error, setError] = useState<AnalysisError | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [timing, setTiming] = useState<RequestTimingState>({ sequence: 0, modelProcessingMs: null, clientRoundTripMs: null });
  const abortRef = useRef<AbortController | null>(null);
  const requestSequenceRef = useRef(0);
  const emlInputRef = useRef<HTMLInputElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    setMode(readPreferences().defaultAnalysisMode);
  }, []);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (!isLoading) return;
    const stageTimer = window.setInterval(() => setStageIndex((current) => (current + 1) % stages.length), 1400);
    const elapsedTimer = window.setInterval(() => setElapsed((current) => current + 0.1), 100);
    return () => {
      window.clearInterval(stageTimer);
      window.clearInterval(elapsedTimer);
    };
  }, [isLoading]);

  const invalidateActiveRequest = () => {
    requestSequenceRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    setIsLoading(false);
    setTiming({ sequence: requestSequenceRef.current, modelProcessingMs: null, clientRoundTripMs: null });
  };

  const selectMode = (nextMode: AnalysisInputMode) => {
    if (nextMode === mode) return;
    invalidateActiveRequest();
    setMode(nextMode);
    setError(null);
    setResult(null);
    setResultAttachmentCount(0);
  };

  const onModeKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % modes.length;
    if (event.key === 'ArrowLeft') nextIndex = (index - 1 + modes.length) % modes.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = modes.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    selectMode(modes[nextIndex].id);
    window.requestAnimationFrame(() => tabRefs.current[nextIndex]?.focus());
  };

  const updateQuick = (field: QuickPasteField, value: string) => {
    setQuick((current) => ({ ...current, [field]: value }));
    if (error?.field === field) setError(null);
  };

  const onAttachmentsSelected = (event: ChangeEvent<HTMLInputElement>) => {
    const selection = mergeAttachmentSelection(attachments, event.target.files ?? []);
    setAttachments(selection.attachments);
    setError(selection.errors.length ? { field: 'quickAttachments', message: selection.errors.join(' ') } : null);
    event.target.value = '';
  };

  const focusErrorField = (field: ErrorField) => {
    const id = field === 'rawSource' ? 'raw-email-source' : field === 'emlFile' ? 'eml-file-input' : field === 'quickAttachments' ? 'quick-attachments' : `quick-${field}`;
    window.requestAnimationFrame(() => document.getElementById(id)?.focus());
  };

  const loadEml = async (file: File) => {
    setError(null);
    setResult(null);
    setResultAttachmentCount(0);
    setTiming((current) => ({ ...current, modelProcessingMs: null, clientRoundTripMs: null }));
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError({ field: 'emlFile', message: 'Choose a file with the .eml extension.' });
      focusErrorField('emlFile');
      return;
    }
    if (file.size > MAX_EMAIL_BYTES) {
      setError({ field: 'emlFile', message: 'This email exceeds the 2 MB processing limit.' });
      focusErrorField('emlFile');
      return;
    }
    const text = await file.text();
    if (!text.trim()) {
      setError({ field: 'emlFile', message: 'The selected .eml file is empty.' });
      focusErrorField('emlFile');
      return;
    }
    setRawSource(text);
    setSelectedFile({ name: file.name, size: file.size });
  };

  const onEmlSelected = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) void loadEml(file);
    event.target.value = '';
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    abortRef.current?.abort();
    const nextTiming = beginRequest(requestSequenceRef.current);
    requestSequenceRef.current = nextTiming.sequence;
    const requestSequence = nextTiming.sequence;
    setTiming(nextTiming);
    setResult(null);
    setResultAttachmentCount(0);
    setError(null);

    if (mode === 'quick_paste') {
      const problem = validateQuickPaste(quick);
      if (problem) {
        setError(problem);
        focusErrorField(problem.field);
        return;
      }
    } else if (!rawSource.trim()) {
      const field = mode === 'eml_upload' ? 'emlFile' : 'rawSource';
      setError({ field, message: mode === 'eml_upload' ? 'Choose a non-empty .eml file.' : 'Paste the complete raw email source.' });
      focusErrorField(field);
      return;
    }

    const attachmentMetadata = mode === 'quick_paste' ? toAttachmentMetadataPayload(attachments) : [];
    const rawEmail = mode === 'quick_paste' ? buildQuickPasteRawEmail(quick, attachmentMetadata) : rawSource;
    if (new TextEncoder().encode(rawEmail).length > MAX_EMAIL_BYTES) {
      const field = mode === 'quick_paste' ? 'body' : mode === 'raw_email' ? 'rawSource' : 'emlFile';
      setError({ field, message: 'This email exceeds the 2 MB processing limit.' });
      focusErrorField(field);
      return;
    }

    const controller = new AbortController();
    abortRef.current = controller;
    setIsLoading(true);
    setElapsed(0);
    setStageIndex(0);
    const startedAt = performance.now();

    try {
      const response = await analyzeProductionEmail(rawEmail, controller.signal);
      if (!isCurrentRequest(requestSequenceRef.current, requestSequence) || controller.signal.aborted) return;
      const clientRoundTripMs = performance.now() - startedAt;
      setResult(response);
      setResultAttachmentCount(attachmentMetadata.length);
      setTiming((current) => completeRequestTiming(current, requestSequence, response.processing_time_ms, clientRoundTripMs));
      if (readPreferences().saveSuccessfulScans) {
        saveScan(createProductionScanRecord(response, rawEmail, mode, attachmentMetadata));
      }
    } catch (caught) {
      if (!isCurrentRequest(requestSequenceRef.current, requestSequence)) return;
      setResult(null);
      setResultAttachmentCount(0);
      setTiming((current) => clearRequestTiming(current, requestSequence));
      if (!(caught instanceof ApiError && caught.kind === 'cancelled')) {
        setError({ message: caught instanceof ApiError ? caught.message : 'Analysis failed safely. Please try again.' });
      }
    } finally {
      if (isCurrentRequest(requestSequenceRef.current, requestSequence)) {
        abortRef.current = null;
        setIsLoading(false);
      }
    }
  };

  const cancel = () => {
    invalidateActiveRequest();
    setResult(null);
    setResultAttachmentCount(0);
    setError(null);
  };

  const clear = () => {
    invalidateActiveRequest();
    setQuick(emptyQuickPaste);
    setAttachments(clearSelectedAttachments());
    setRawSource('');
    setSelectedFile(null);
    setResult(null);
    setResultAttachmentCount(0);
    setError(null);
    if (emlInputRef.current) emlInputRef.current.value = '';
    if (attachmentInputRef.current) attachmentInputRef.current.value = '';
  };

  const activeMode = modes.find((item) => item.id === mode) ?? modes[0];
  const ActiveModeIcon = activeMode.icon;

  return (
    <main className="mx-auto max-w-6xl space-y-8">
      <div className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Production inference workspace</p><h1 className="mt-2 text-3xl font-semibold text-foreground">Analyze an email</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Select an input mode. Only the active mode is submitted to the production analyzer.</p></div>
        <BackendStatus />
      </div>

      <form noValidate onSubmit={submit} className="space-y-6 rounded-xl border border-border bg-surface/75 p-5 shadow-xl sm:p-7">
        <div>
          <div className="grid gap-2 sm:grid-cols-3" role="tablist" aria-label="Input mode">
            {modes.map((item, index) => {
              const active = item.id === mode;
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  ref={(node) => { tabRefs.current[index] = node; }}
                  id={`mode-tab-${item.id}`}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  aria-controls={`mode-panel-${item.id}`}
                  tabIndex={active ? 0 : -1}
                  onClick={() => selectMode(item.id)}
                  onKeyDown={(event) => onModeKeyDown(event, index)}
                  className={`flex min-h-12 items-center justify-between gap-3 rounded-lg border px-4 py-3 text-left text-sm font-semibold transition-[background-color,border-color,color,box-shadow,transform] active:scale-[0.99] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${active ? 'border-primary bg-primary text-primary-foreground shadow-[inset_0_0_0_1px_rgb(var(--color-primary))]' : 'border-border bg-background/70 text-muted-foreground hover:border-input hover:bg-surface-muted hover:text-foreground'}`}
                >
                  <span className="flex items-center gap-2"><Icon className="h-4 w-4" aria-hidden="true" />{item.label}</span>
                  {active && <Check className="h-4 w-4 shrink-0" aria-label="Selected" />}
                </button>
              );
            })}
          </div>
          <p className="mt-3 flex items-center gap-2 text-sm font-medium text-foreground" aria-live="polite"><CheckCircle2 className="h-4 w-4 text-primary" aria-hidden="true" />Current input mode: {activeMode.label}</p>
        </div>

        {mode === 'quick_paste' && (
          <section id="mode-panel-quick_paste" role="tabpanel" aria-labelledby="mode-tab-quick_paste" className="space-y-4">
            <p className="text-sm leading-6 text-muted-foreground">Use Quick Paste for copied inbox content. Full message headers are not available, so some authentication and routing checks may be unavailable.</p>
            <div className="grid gap-4 md:grid-cols-2">
              {([
                ['senderName', 'Sender name', 'text'],
                ['senderEmail', 'Sender email', 'email'],
                ['recipientName', 'Recipient name (optional)', 'text'],
                ['recipientEmail', 'Recipient email (optional)', 'email'],
                ['replyTo', 'Reply-To (optional)', 'email'],
                ['subject', 'Subject', 'text'],
              ] as Array<[QuickPasteField, string, 'text' | 'email']>).map(([field, label, type]) => (
                <label key={field} htmlFor={`quick-${field}`} className="space-y-1.5 text-sm text-muted-foreground">
                  <span>{label}</span>
                  <input
                    id={`quick-${field}`}
                    type={type}
                    value={quick[field]}
                    onChange={(event) => updateQuick(field, event.target.value)}
                    aria-invalid={error?.field === field || undefined}
                    aria-describedby={error?.field === field ? 'analysis-error' : undefined}
                    className="w-full rounded-md border border-input bg-background px-3 py-2.5 text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-ring/30 aria-[invalid=true]:border-danger"
                  />
                </label>
              ))}
            </div>
            <label htmlFor="quick-body" className="block space-y-1.5 text-sm text-muted-foreground">
              <span>Email body</span>
              <textarea id="quick-body" value={quick.body} onChange={(event) => updateQuick('body', event.target.value)} aria-invalid={error?.field === 'body' || undefined} aria-describedby={error?.field === 'body' ? 'analysis-error' : undefined} className="min-h-48 w-full resize-y rounded-md border border-input bg-background p-3 text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-ring/30 aria-[invalid=true]:border-danger" />
            </label>

            <section className="rounded-lg border border-border p-4" aria-labelledby="quick-attachments-heading">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div><h2 id="quick-attachments-heading" className="text-sm font-semibold text-foreground">Attachments <span className="font-normal text-muted-foreground">(optional)</span></h2><p className="mt-1 max-w-2xl text-xs leading-5 text-muted-foreground">Only attachment metadata is included. Attachment contents are not uploaded, opened, or scanned.</p></div>
                <input ref={attachmentInputRef} id="quick-attachments" type="file" multiple onChange={onAttachmentsSelected} className="sr-only" aria-describedby={error?.field === 'quickAttachments' ? 'analysis-error' : undefined} />
                <button type="button" onClick={() => attachmentInputRef.current?.click()} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-md border border-input bg-background px-3 py-2 text-sm font-medium text-foreground hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><Paperclip className="h-4 w-4" aria-hidden="true" />Add attachments</button>
              </div>
              {attachments.length > 0 && <ul className="mt-4 grid gap-2 md:grid-cols-2">{attachments.map(({ key, metadata }) => <li key={key} className="flex min-w-0 items-center gap-3 rounded-lg border border-border bg-background/60 p-3"><Paperclip className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium text-foreground">{metadata.filename}</p><p className="mt-0.5 truncate text-xs text-muted-foreground">{extensionLabel(metadata.filename, metadata.content_type)} · {formatFileSize(metadata.size_bytes)}</p></div><button type="button" aria-label={`Remove ${metadata.filename}`} onClick={() => setAttachments(removeSelectedAttachment(attachments, key))} className="rounded-md p-2 text-muted-foreground hover:bg-danger/10 hover:text-danger focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><X className="h-4 w-4" aria-hidden="true" /></button></li>)}</ul>}
            </section>
          </section>
        )}

        {mode === 'raw_email' && (
          <section id="mode-panel-raw_email" role="tabpanel" aria-labelledby="mode-tab-raw_email">
            <p className="mb-3 text-sm leading-6 text-muted-foreground">Paste the complete RFC822 message source. Copied inbox content belongs in Quick Paste.</p>
            <textarea id="raw-email-source" aria-label="Raw email source" value={rawSource} onChange={(event) => { setRawSource(event.target.value); if (error?.field === 'rawSource') setError(null); }} aria-invalid={error?.field === 'rawSource' || undefined} aria-describedby={error?.field === 'rawSource' ? 'analysis-error' : undefined} className="min-h-[420px] w-full resize-y overflow-auto rounded-lg border border-input bg-background p-4 font-mono text-xs leading-6 text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-ring/30 aria-[invalid=true]:border-danger" />
            <p className="mt-2 text-xs text-muted-foreground">{rawSource.length.toLocaleString()} characters · 2 MB maximum</p>
          </section>
        )}

        {mode === 'eml_upload' && (
          <section id="mode-panel-eml_upload" role="tabpanel" aria-labelledby="mode-tab-eml_upload">
            <div onDragOver={(event) => { event.preventDefault(); event.currentTarget.classList.add('border-primary'); }} onDragLeave={(event) => event.currentTarget.classList.remove('border-primary')} onDrop={(event) => { event.preventDefault(); event.currentTarget.classList.remove('border-primary'); const file = event.dataTransfer.files[0]; if (file) void loadEml(file); }} className="flex min-h-64 flex-col items-center justify-center rounded-xl border-2 border-dashed border-input p-8 text-center transition">
              <Upload className="h-10 w-10 text-primary" aria-hidden="true" />
              <h2 className="mt-4 text-lg font-semibold text-foreground">Drop an .eml file here</h2>
              <p className="mt-2 text-sm text-muted-foreground">Maximum size 2 MB. The email source is read in memory only.</p>
              <button type="button" onClick={() => emlInputRef.current?.click()} className="mt-5 rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">Choose file</button>
              <input ref={emlInputRef} id="eml-file-input" type="file" accept=".eml,message/rfc822" className="sr-only" aria-label="Choose an EML file" aria-describedby={error?.field === 'emlFile' ? 'analysis-error' : undefined} onChange={onEmlSelected} />
            </div>
            {selectedFile && <div className="mt-4 flex items-center justify-between rounded-lg border border-border bg-background/60 p-4"><div className="min-w-0"><p className="break-words text-sm text-foreground">{selectedFile.name}</p><p className="text-xs text-muted-foreground">{formatFileSize(selectedFile.size)}</p></div><button type="button" aria-label="Remove selected file" onClick={() => { setSelectedFile(null); setRawSource(''); if (emlInputRef.current) emlInputRef.current.value = ''; }} className="rounded p-2 text-muted-foreground hover:bg-danger/10 hover:text-danger focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><X className="h-4 w-4" /></button></div>}
          </section>
        )}

        {error && <p id="analysis-error" role="alert" className="rounded-md border border-danger/30 bg-danger/10 p-3 text-sm text-danger">{error.message}</p>}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5">
          <div className="flex flex-wrap gap-2">
            {mode === 'raw_email' && <button type="button" onClick={() => { setRawSource(EXAMPLE_EMAIL); setError(null); }} disabled={isLoading} className="inline-flex items-center gap-2 rounded-md border border-input px-3 py-2 text-sm hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><ClipboardPaste className="h-4 w-4" />Use safe example</button>}
            <button type="button" onClick={clear} className="inline-flex items-center gap-2 rounded-md border border-input px-3 py-2 text-sm hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><RotateCcw className="h-4 w-4" />Clear</button>
            {isLoading && <button type="button" onClick={cancel} className="inline-flex items-center gap-2 rounded-md border border-danger/40 px-3 py-2 text-sm font-medium text-danger hover:bg-danger/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><X className="h-4 w-4" />Cancel analysis</button>}
          </div>
          <button type="submit" disabled={isLoading} className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 py-2 text-sm font-semibold text-primary-foreground transition active:scale-[0.98] hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50">{isLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Analyzing {activeMode.label}</> : <><ActiveModeIcon className="h-4 w-4" />{activeMode.actionLabel}</>}</button>
        </div>
      </form>

      {!result && !isLoading && <div className="flex min-h-36 items-center justify-center rounded-xl border border-dashed border-border bg-surface/30 px-6 text-center text-sm text-muted-foreground"><CheckCircle2 className="mr-2 h-5 w-5" />Your analysis result will appear below the input workspace.</div>}
      {isLoading && <div className="rounded-xl border border-primary/30 bg-primary/10 p-6" role="status" aria-live="polite"><div className="flex items-center gap-3"><Loader2 className="h-5 w-5 animate-spin text-primary" /><span className="font-semibold text-foreground">{stages[stageIndex]}</span><span className="ml-auto text-xs tabular-nums text-muted-foreground">{elapsed.toFixed(1)}s</span></div></div>}
      {result && <ProductionAnalysisResults result={result} clientRoundTripMs={timing.clientRoundTripMs} attachmentCount={resultAttachmentCount} />}
    </main>
  );
}
