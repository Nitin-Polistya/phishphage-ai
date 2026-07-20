'use client';

import {
  ChangeEvent,
  DragEvent,
  FormEvent,
  KeyboardEvent,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  AlertCircle,
  AlertTriangle,
  FileText,
  Loader2,
  Mail,
  Paperclip,
  Send,
  Trash2,
  UploadCloud,
  X,
} from 'lucide-react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { ApiError, analyzeEmail, type ApiErrorKind } from '@/lib/api';
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
import { createScanRecord, saveScan } from '@/lib/scan-store';
import { cn } from '@/lib/utils';
import type { AnalysisInputMode, UnifiedAnalysisResponse } from '@/types/analysis';
import { AnalysisResults } from './analysis-results';

const MAX_FILE_SIZE = 2 * 1024 * 1024;
const RAW_SOURCE_GUIDANCE = "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from 'Show original' / 'View source'.";
const sourceHeaders = new Set(['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type']);
const modes: Array<{ id: AnalysisInputMode; label: string; description: string; icon: typeof Mail }> = [
  { id: 'quick_paste', label: 'Quick Paste', description: 'Visible message text and optional metadata', icon: Mail },
  { id: 'raw_email', label: 'Raw Email', description: 'Complete RFC822 message source', icon: FileText },
  { id: 'eml_upload', label: '.eml Upload', description: 'A saved email file, up to 2 MB', icon: Paperclip },
];

type AnalysisError = { kind: ApiErrorKind | 'file'; message: string };

function isLikelyRfc822Source(value: string) {
  const headerBlock = value.split(/\r?\n\r?\n/, 1)[0] ?? '';
  const recognized = new Set<string>();
  for (const line of headerBlock.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z0-9-]+):/);
    if (match && sourceHeaders.has(match[1].toLowerCase())) recognized.add(match[1].toLowerCase());
  }
  return recognized.size >= 2;
}

function optional(value: string) {
  const trimmed = value.trim();
  return trimmed || undefined;
}

function FieldLabel({ htmlFor, children, optionalField = false }: { htmlFor: string; children: string; optionalField?: boolean }) {
  return (
    <Label htmlFor={htmlFor} className="flex items-center gap-2 text-sm text-muted-foreground">
      {children}
      {optionalField && <span className="text-[11px] font-normal text-foreground0">Optional</span>}
    </Label>
  );
}

export function AnalysisForm() {
  const [mode, setMode] = useState<AnalysisInputMode>('quick_paste');
  const [quick, setQuick] = useState({ sender_name: '', sender_email: '', recipient_name: '', recipient_email: '', reply_to: '', subject: '', body: '' });
  const [attachments, setAttachments] = useState<SelectedQuickAttachment[]>([]);
  const [rawEmail, setRawEmail] = useState('');
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [emlText, setEmlText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AnalysisError | null>(null);
  const [result, setResult] = useState<UnifiedAnalysisResponse | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const quickAttachmentInput = useRef<HTMLInputElement>(null);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    setMode(readPreferences().defaultAnalysisMode);
  }, []);

  const selectMode = (nextMode: AnalysisInputMode) => {
    if (mode === 'quick_paste' && nextMode !== 'quick_paste') {
      setAttachments(clearSelectedAttachments());
      if (quickAttachmentInput.current) quickAttachmentInput.current.value = '';
    }
    if (mode === 'eml_upload' && nextMode !== 'eml_upload') {
      setEmlFile(null);
      setEmlText('');
      if (fileInput.current) fileInput.current.value = '';
    }
    setMode(nextMode);
    setError(null);
    setResult(null);
  };

  const moveTabFocus = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % modes.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + modes.length) % modes.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = modes.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    selectMode(modes[nextIndex].id);
    tabRefs.current[nextIndex]?.focus();
  };

  const onQuickAttachmentsSelected = (event: ChangeEvent<HTMLInputElement>) => {
    const selection = mergeAttachmentSelection(attachments, event.target.files ?? []);
    setAttachments(selection.attachments);
    setError(selection.errors.length ? { kind: 'file', message: selection.errors.join(' ') } : null);
    setResult(null);
    event.target.value = '';
  };

  const loadEml = async (file: File) => {
    setError(null);
    setResult(null);
    setEmlFile(null);
    setEmlText('');
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError({ kind: 'file', message: 'Choose a file with the .eml extension.' });
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError({ kind: 'file', message: 'The .eml file exceeds the 2 MB limit.' });
      return;
    }
    setEmlFile(file);
    setEmlText(await file.text());
  };

  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) void loadEml(file);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) void loadEml(file);
  };

  const canAnalyze = mode === 'quick_paste' ? Boolean(quick.body.trim()) : mode === 'raw_email' ? Boolean(rawEmail.trim()) : Boolean(emlFile && emlText);

  const handleAnalyze = async () => {
    if (isLoading) return;
    if (!canAnalyze) {
      setError({ kind: 'validation', message: mode === 'eml_upload' ? 'Choose a valid .eml file to analyze.' : 'Provide email content to analyze.' });
      return;
    }
    if (mode === 'raw_email' && !isLikelyRfc822Source(rawEmail)) {
      setError({ kind: 'validation', message: RAW_SOURCE_GUIDANCE });
      setResult(null);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const analysis = await analyzeEmail(mode === 'quick_paste'
        ? {
          input_mode: mode,
          sender_name: optional(quick.sender_name),
          sender_email: optional(quick.sender_email),
          recipient_name: optional(quick.recipient_name),
          recipient_email: optional(quick.recipient_email),
          reply_to: optional(quick.reply_to),
          subject: optional(quick.subject),
          body: quick.body,
          attachments: toAttachmentMetadataPayload(attachments),
        }
        : { input_mode: mode, raw_email: mode === 'raw_email' ? rawEmail : emlText });
      setResult(analysis);
      if (readPreferences().saveSuccessfulScans) saveScan(createScanRecord(analysis, mode));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError
        ? { kind: caught.kind, message: caught.message }
        : { kind: 'unexpected', message: 'Unexpected analysis error. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void handleAnalyze();
  };

  const handleClear = () => {
    setQuick({ sender_name: '', sender_email: '', recipient_name: '', recipient_email: '', reply_to: '', subject: '', body: '' });
    setAttachments(clearSelectedAttachments());
    setRawEmail('');
    setEmlFile(null);
    setEmlText('');
    setError(null);
    setResult(null);
    if (fileInput.current) fileInput.current.value = '';
    if (quickAttachmentInput.current) quickAttachmentInput.current.value = '';
  };

  const errorTitle = error?.kind === 'backend_unavailable'
    ? 'Analysis service is offline'
    : error?.kind === 'service_unavailable'
      ? 'Analysis service is unavailable'
      : error?.kind === 'validation' || error?.kind === 'file'
        ? 'Check your input'
        : 'Unable to analyze email';

  return (
    <div className="analyze-surface space-y-6">
      <Card className="border-border bg-surface/80">
        <CardHeader className="border-b border-border pb-5">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground">Choose an input method</h2>
              <p className="mt-1 text-sm text-muted-foreground">Select the format that best matches the email evidence you have.</p>
            </div>
            <Badge variant="outline" className="w-fit border-input text-muted-foreground">Raw submissions are not stored</Badge>
          </div>
        </CardHeader>

        <CardContent className="p-5 sm:p-6">
          <div role="tablist" aria-label="Analysis input mode" className="grid gap-2 sm:grid-cols-3">
            {modes.map((item, index) => {
              const Icon = item.icon;
              const active = mode === item.id;
              return (
                <button
                  key={item.id}
                  ref={(element) => { tabRefs.current[index] = element; }}
                  id={`analysis-tab-${item.id}`}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  aria-controls={`analysis-panel-${item.id}`}
                  tabIndex={active ? 0 : -1}
                  disabled={isLoading}
                  onClick={() => selectMode(item.id)}
                  onKeyDown={(event) => moveTabFocus(event, index)}
                  className={cn(
                    'rounded-lg border px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-60',
                    active
                      ? 'border-primary bg-primary/10 text-foreground shadow-sm'
                      : 'border-border bg-background/50 text-muted-foreground hover:border-input hover:bg-background',
                  )}
                >
                  <span className="flex items-center gap-2 text-sm font-semibold"><Icon className={cn('h-4 w-4', active ? 'text-primary' : 'text-foreground0')} aria-hidden="true" />{item.label}</span>
                  <span className="mt-1.5 block text-xs leading-5 text-foreground0">{item.description}</span>
                </button>
              );
            })}
          </div>

          <form onSubmit={handleSubmit} className="mt-6 space-y-6">
            {mode === 'quick_paste' && (
              <section id="analysis-panel-quick_paste" role="tabpanel" aria-labelledby="analysis-tab-quick_paste" className="space-y-6">
                <div className="rounded-lg bg-background/60 p-4 text-sm leading-6 text-muted-foreground">
                  Paste the visible message and add any metadata you know. Missing full-email headers are excluded from header-based checks.
                </div>

                <fieldset className="space-y-4">
                  <legend className="text-sm font-semibold text-foreground">Message details</legend>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-1.5"><FieldLabel htmlFor="sender_name" optionalField>Sender name</FieldLabel><Input id="sender_name" value={quick.sender_name} onChange={(event) => setQuick({ ...quick, sender_name: event.target.value })} placeholder="Jane Smith" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                    <div className="space-y-1.5"><FieldLabel htmlFor="sender_email" optionalField>Sender email</FieldLabel><Input id="sender_email" type="email" value={quick.sender_email} onChange={(event) => setQuick({ ...quick, sender_email: event.target.value })} placeholder="jane@example.com" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                    <div className="space-y-1.5"><FieldLabel htmlFor="recipient_name" optionalField>Recipient name</FieldLabel><Input id="recipient_name" value={quick.recipient_name} onChange={(event) => setQuick({ ...quick, recipient_name: event.target.value })} placeholder="Nitin" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                    <div className="space-y-1.5"><FieldLabel htmlFor="recipient_email" optionalField>Recipient email</FieldLabel><Input id="recipient_email" type="email" value={quick.recipient_email} onChange={(event) => setQuick({ ...quick, recipient_email: event.target.value })} placeholder="you@example.com" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                    <div className="space-y-1.5"><FieldLabel htmlFor="reply_to" optionalField>Reply-To</FieldLabel><Input id="reply_to" type="email" value={quick.reply_to} onChange={(event) => setQuick({ ...quick, reply_to: event.target.value })} placeholder="reply@example.com" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                    <div className="space-y-1.5"><FieldLabel htmlFor="subject" optionalField>Subject</FieldLabel><Input id="subject" value={quick.subject} onChange={(event) => setQuick({ ...quick, subject: event.target.value })} placeholder="Email subject" className="border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                  </div>
                  <div className="space-y-1.5"><FieldLabel htmlFor="quick-body">Email body</FieldLabel><Textarea id="quick-body" required value={quick.body} onChange={(event) => setQuick({ ...quick, body: event.target.value })} placeholder="Paste the visible email body..." className="min-h-52 resize-y border-input bg-background text-foreground placeholder:text-muted-foreground" /></div>
                </fieldset>

                <Separator className="bg-surface-muted" />
                <section aria-labelledby="quick-attachments-heading" className="space-y-3">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div><h3 id="quick-attachments-heading" className="text-sm font-semibold text-foreground">Attachment metadata <span className="font-normal text-foreground0">(optional)</span></h3><p className="mt-1 text-xs leading-5 text-foreground0">Only filenames, types, and sizes are analyzed. File contents are never uploaded.</p></div>
                    <Input ref={quickAttachmentInput} type="file" multiple onChange={onQuickAttachmentsSelected} className="sr-only" id="quick-attachments" />
                    <Button type="button" variant="outline" size="sm" onClick={() => quickAttachmentInput.current?.click()} className="shrink-0 border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Paperclip aria-hidden="true" />Add attachments</Button>
                  </div>
                  {attachments.length > 0 && <ul className="grid gap-2 md:grid-cols-2">
                    {attachments.map(({ key, metadata }) => (
                      <li key={key} className="flex min-w-0 items-center justify-between gap-3 rounded-lg bg-background/60 px-3 py-3">
                        <div className="min-w-0">
                          <div className="flex min-w-0 items-center gap-2"><p className="truncate text-sm font-medium text-foreground" title={metadata.filename ?? undefined}>{metadata.filename}</p><Badge variant="outline" className={cn('shrink-0', metadata.suspicious_extension ? 'border-danger/30 bg-danger/10 text-danger' : 'border-input text-muted-foreground')}>{metadata.extension || 'no extension'}</Badge></div>
                          <p className="mt-1 truncate text-xs text-foreground0">{metadata.content_type} - {formatFileSize(metadata.size_bytes)}</p>
                          {metadata.suspicious_extension && <p className="mt-1 flex items-center gap-1.5 text-xs text-danger"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />Potentially risky extension</p>}
                        </div>
                        <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${metadata.filename}`} onClick={() => setAttachments(removeSelectedAttachment(attachments, key))} className="shrink-0 text-foreground0 hover:bg-danger/10 hover:text-danger"><X aria-hidden="true" /></Button>
                      </li>
                    ))}
                  </ul>}
                </section>
              </section>
            )}

            {mode === 'raw_email' && (
              <section id="analysis-panel-raw_email" role="tabpanel" aria-labelledby="analysis-tab-raw_email" className="space-y-3">
                <div className="rounded-lg bg-background/60 p-4 text-sm leading-6 text-muted-foreground">Paste the complete source from <span className="font-medium text-muted-foreground">Show original</span> or <span className="font-medium text-muted-foreground">View message source</span>. At least two recognizable headers are required.</div>
                <FieldLabel htmlFor="raw-email">Raw email source</FieldLabel>
                <Textarea id="raw-email" required value={rawEmail} onChange={(event) => setRawEmail(event.target.value)} placeholder={'From: sender@example.com\nSubject: Message subject\n\nEmail body'} className="min-h-[360px] resize-y border-input bg-background p-4 font-mono text-xs leading-5 text-foreground placeholder:text-muted-foreground sm:min-h-[420px]" />
              </section>
            )}

            {mode === 'eml_upload' && (
              <section id="analysis-panel-eml_upload" role="tabpanel" aria-labelledby="analysis-tab-eml_upload" className="space-y-4">
                <div onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }} onDragLeave={() => setIsDragging(false)} onDrop={onDrop} className={cn('flex min-h-56 flex-col items-center justify-center rounded-lg border border-dashed p-6 text-center transition-colors sm:min-h-64 sm:p-8', isDragging ? 'border-primary bg-primary/10' : 'border-input bg-background/50')}>
                  <UploadCloud className="h-9 w-9 text-foreground0" aria-hidden="true" />
                  <p className="mt-4 text-sm font-medium text-foreground">Drop an .eml file here</p>
                  <p className="mt-1 max-w-md text-xs leading-5 text-foreground0">Maximum 2 MB. Parsed in memory; attachment contents are never executed.</p>
                  <Input ref={fileInput} type="file" accept=".eml,message/rfc822" onChange={onFileChange} className="sr-only" id="eml-file" />
                  <Button type="button" variant="outline" size="sm" onClick={() => fileInput.current?.click()} className="mt-4 border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Paperclip aria-hidden="true" />Choose file</Button>
                </div>
                {emlFile && <div className="flex items-center justify-between gap-3 rounded-lg bg-background/60 px-4 py-3"><div className="min-w-0"><p className="truncate text-sm font-medium text-foreground" title={emlFile.name}>{emlFile.name}</p><p className="mt-1 text-xs text-foreground0">{formatFileSize(emlFile.size)} - ready to analyze</p></div><Button type="button" variant="ghost" size="icon" onClick={() => { setEmlFile(null); setEmlText(''); if (fileInput.current) fileInput.current.value = ''; }} aria-label="Remove selected file" className="shrink-0 text-foreground0 hover:bg-danger/10 hover:text-danger"><X aria-hidden="true" /></Button></div>}
              </section>
            )}

            {error && (
              <Alert id="analysis-error" className="border-danger/30 bg-danger/10 text-danger">
                <AlertCircle aria-hidden="true" />
                <AlertTitle>{errorTitle}</AlertTitle>
                <AlertDescription className="pr-2">
                  <p>{error.message}</p>
                  {(error.kind === 'backend_unavailable' || error.kind === 'service_unavailable' || error.kind === 'unexpected') && (
                    <Button type="submit" variant="outline" size="sm" disabled={isLoading || !canAnalyze} className="mt-3 border-danger/30 bg-transparent text-danger hover:bg-danger/10 hover:text-foreground">Try again</Button>
                  )}
                </AlertDescription>
              </Alert>
            )}

            {isLoading && (
              <div role="status" aria-live="polite" className="rounded-lg bg-primary/10 p-4">
                <div className="flex items-center gap-3"><Loader2 className="h-5 w-5 animate-spin text-primary" aria-hidden="true" /><div><p className="text-sm font-medium text-foreground">Analyzing email</p><p className="mt-0.5 text-xs text-muted-foreground">Parsing content and evaluating security signals...</p></div></div>
                <Progress value={100} className="mt-3 h-1 bg-surface-muted [&>div]:animate-pulse [&>div]:bg-primary" aria-label="Analysis in progress" />
              </div>
            )}

            <div className="flex flex-col-reverse gap-3 border-t border-border pt-5 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                {mode === 'raw_email' && <Button type="button" variant="ghost" size="sm" onClick={() => { setRawEmail(EXAMPLE_EMAIL); setError(null); setResult(null); }} disabled={isLoading} className="text-muted-foreground hover:bg-surface-muted hover:text-foreground">Load example</Button>}
                <Button type="button" variant="ghost" size="sm" onClick={handleClear} disabled={isLoading} className="text-foreground0 hover:bg-surface-muted hover:text-foreground"><Trash2 aria-hidden="true" />Clear</Button>
              </div>
              <Button type="submit" disabled={isLoading || !canAnalyze} aria-describedby={error ? 'analysis-error' : undefined} className="w-full bg-primary text-primary-foreground hover:bg-primary sm:w-auto">{isLoading ? <><Loader2 className="animate-spin" aria-hidden="true" />Analyzing...</> : <><Send aria-hidden="true" />Analyze email</>}</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <AnalysisResults result={result} isLoading={isLoading} />
    </div>
  );
}
