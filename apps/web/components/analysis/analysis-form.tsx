"use client";

import { ChangeEvent, DragEvent, useRef, useState } from 'react';
import { AlertTriangle, FileText, Loader2, Mail, Paperclip, Send, Trash2, UploadCloud, X } from 'lucide-react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { ApiError, analyzeEmail } from '@/lib/api';
import {
  clearSelectedAttachments,
  formatFileSize,
  mergeAttachmentSelection,
  removeSelectedAttachment,
  toAttachmentMetadataPayload,
  type SelectedQuickAttachment,
} from '@/lib/attachment-metadata';
import { MOCK_EXAMPLE_EMAIL } from '@/lib/mock-data';
import { cn } from '@/lib/utils';
import type { AnalysisInputMode, UnifiedAnalysisResponse } from '@/types/analysis';
import { AnalysisResults } from './analysis-results';

const MAX_FILE_SIZE = 2 * 1024 * 1024;
const RAW_SOURCE_GUIDANCE = "This looks like copied inbox text, not full email source. Use Quick Paste, or paste the message from 'Show original' / 'View source'.";
const sourceHeaders = new Set(['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type']);
const modes: Array<{ id: AnalysisInputMode; label: string; description: string; icon: typeof Mail }> = [
  { id: 'quick_paste', label: 'Quick Paste', description: 'Copied inbox text', icon: Mail },
  { id: 'raw_email', label: 'Raw Email', description: 'Full message source', icon: FileText },
  { id: 'eml_upload', label: 'Upload .eml', description: 'Local email file', icon: Paperclip },
];

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

export function AnalysisForm() {
  const [mode, setMode] = useState<AnalysisInputMode>('quick_paste');
  const [quick, setQuick] = useState({ sender_name: '', sender_email: '', recipient_name: '', recipient_email: '', reply_to: '', subject: '', body: '' });
  const [attachments, setAttachments] = useState<SelectedQuickAttachment[]>([]);
  const [rawEmail, setRawEmail] = useState('');
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [emlText, setEmlText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UnifiedAnalysisResponse | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const quickAttachmentInput = useRef<HTMLInputElement>(null);

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

  const onQuickAttachmentsSelected = (event: ChangeEvent<HTMLInputElement>) => {
    const selection = mergeAttachmentSelection(attachments, event.target.files ?? []);
    setAttachments(selection.attachments);
    setError(selection.errors.length ? selection.errors.join(' ') : null);
    setResult(null);
    event.target.value = '';
  };

  const loadEml = async (file: File) => {
    setError(null);
    setResult(null);
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError('Choose a file with the .eml extension.');
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError('The .eml file exceeds the 2 MB limit.');
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
    if (!canAnalyze) {
      setError(mode === 'eml_upload' ? 'Choose a valid .eml file to analyze.' : 'Provide email content to analyze.');
      return;
    }
    if (mode === 'raw_email' && !isLikelyRfc822Source(rawEmail)) {
      setError(RAW_SOURCE_GUIDANCE);
      setResult(null);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      setResult(await analyzeEmail(mode === 'quick_paste'
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
        : { input_mode: mode, raw_email: mode === 'raw_email' ? rawEmail : emlText }));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError ? caught.message : 'Unexpected analysis error. Please try again.');
    } finally {
      setIsLoading(false);
    }
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

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-12">
        <Card className="border-slate-800 bg-slate-900/80 xl:col-span-7">
          <CardHeader className="border-b border-slate-800 pb-4">
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-base text-slate-100">Email input</CardTitle>
              <Badge variant="outline" className="border-slate-700 text-slate-400">No content is stored</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-5 p-5">
            <div role="tablist" aria-label="Analysis input mode" className="grid grid-cols-3 gap-1 rounded-lg border border-slate-800 bg-slate-950 p-1">
              {modes.map((item) => {
                const Icon = item.icon;
                return (
                  <button key={item.id} type="button" role="tab" aria-selected={mode === item.id} onClick={() => selectMode(item.id)} className={cn('rounded-md px-2 py-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500', mode === item.id ? 'bg-slate-800 text-slate-100' : 'text-slate-500 hover:text-slate-300')}>
                    <span className="flex items-center justify-center gap-2 text-xs font-semibold sm:justify-start sm:text-sm"><Icon className="h-4 w-4" aria-hidden="true" />{item.label}</span>
                    <span className="mt-1 hidden text-xs text-slate-500 sm:block">{item.description}</span>
                  </button>
                );
              })}
            </div>

            {mode === 'quick_paste' && (
              <div role="tabpanel" className="space-y-4">
                <p className="text-xs leading-5 text-slate-400">For copied inbox content. Missing RFC822 headers are intentionally excluded from risk scoring.</p>
                <div className="grid gap-4 sm:grid-cols-2">
                  {([
                    ['sender_name', 'Sender name', 'Jane Smith', 'text'],
                    ['sender_email', 'Sender email', 'jane@example.com', 'email'],
                    ['recipient_name', 'Recipient name (optional)', 'Nitin', 'text'],
                    ['recipient_email', 'Recipient email (optional)', 'you@example.com', 'email'],
                    ['reply_to', 'Reply-To (optional)', 'reply@example.com', 'email'],
                  ] as const).map(([field, label, placeholder, type]) => (
                    <div key={field} className="space-y-2"><Label htmlFor={field} className="text-slate-300">{label}</Label><Input id={field} type={type} value={quick[field]} onChange={(event) => setQuick({ ...quick, [field]: event.target.value })} placeholder={placeholder} className="border-slate-700 bg-slate-950 text-slate-200 placeholder:text-slate-600" /></div>
                  ))}
                </div>
                <div className="space-y-2"><Label htmlFor="subject" className="text-slate-300">Subject</Label><Input id="subject" value={quick.subject} onChange={(event) => setQuick({ ...quick, subject: event.target.value })} placeholder="Email subject" className="border-slate-700 bg-slate-950 text-slate-200 placeholder:text-slate-600" /></div>
                <div className="space-y-2"><Label htmlFor="quick-body" className="text-slate-300">Email body</Label><Textarea id="quick-body" value={quick.body} onChange={(event) => setQuick({ ...quick, body: event.target.value })} placeholder="Paste the visible email body…" className="min-h-52 resize-y border-slate-700 bg-slate-950 text-slate-200 placeholder:text-slate-600" /></div>

                <Separator className="bg-slate-800" />
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div><p className="text-sm font-medium text-slate-200">Attachments</p><p className="mt-1 text-xs leading-5 text-slate-500">Only file metadata is analyzed in Quick Paste mode. File contents are not uploaded or scanned.</p></div>
                  <Input ref={quickAttachmentInput} type="file" multiple onChange={onQuickAttachmentsSelected} className="sr-only" id="quick-attachments" />
                  <Button type="button" variant="outline" size="sm" onClick={() => quickAttachmentInput.current?.click()} className="border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white"><Paperclip />Add attachments</Button>
                </div>
                {attachments.length > 0 && <div className="space-y-2">
                  {attachments.map(({ key, metadata }) => (
                    <div key={key} className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2.5">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate text-sm font-medium text-slate-200">{metadata.filename}</p>
                          <Badge variant="outline" className={metadata.suspicious_extension ? 'border-rose-500/30 bg-rose-500/10 text-rose-300' : 'border-slate-700 text-slate-400'}>{metadata.extension || 'no extension'}</Badge>
                        </div>
                        <p className="mt-1 text-xs text-slate-500">{metadata.content_type} · {formatFileSize(metadata.size_bytes)}</p>
                        {metadata.suspicious_extension && <p className="mt-1 flex items-center gap-1.5 text-xs text-rose-300"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />Potentially risky file extension</p>}
                      </div>
                      <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${metadata.filename}`} onClick={() => setAttachments(removeSelectedAttachment(attachments, key))} className="shrink-0 text-slate-500 hover:bg-rose-500/10 hover:text-rose-300"><X /></Button>
                    </div>
                  ))}
                </div>}
              </div>
            )}

            {mode === 'raw_email' && (
              <div role="tabpanel" className="space-y-3">
                <p className="text-xs leading-5 text-slate-400">Raw Email requires full RFC822 source from Gmail “Show original” or Outlook “View message source”. Copied sender details such as mailed-by and signed-by belong in Quick Paste.</p>
                <Label htmlFor="raw-email" className="sr-only">Raw email source</Label>
                <Textarea id="raw-email" value={rawEmail} onChange={(event) => setRawEmail(event.target.value)} placeholder={'From: sender@example.com\nSubject: Message subject\n\nEmail body'} className="min-h-[420px] resize-y border-slate-700 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-200 placeholder:text-slate-600" />
              </div>
            )}

            {mode === 'eml_upload' && (
              <div role="tabpanel" className="space-y-4">
                <div onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }} onDragLeave={() => setIsDragging(false)} onDrop={onDrop} className={cn('flex min-h-64 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center transition-colors', isDragging ? 'border-blue-400 bg-blue-500/10' : 'border-slate-700 bg-slate-950/50')}>
                  <UploadCloud className="h-9 w-9 text-slate-500" aria-hidden="true" />
                  <p className="mt-4 text-sm font-medium text-slate-200">Drop an .eml file here</p>
                  <p className="mt-1 text-xs text-slate-500">Maximum 2 MB. Parsed in memory; attachment contents are never executed.</p>
                  <Input ref={fileInput} type="file" accept=".eml,message/rfc822" onChange={onFileChange} className="sr-only" id="eml-file" />
                  <Button type="button" variant="outline" size="sm" onClick={() => fileInput.current?.click()} className="mt-4 border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white"><Paperclip />Choose file</Button>
                </div>
                {emlFile && <div className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950 px-3 py-2"><div className="min-w-0"><p className="truncate text-sm text-slate-200">{emlFile.name}</p><p className="text-xs text-slate-500">{(emlFile.size / 1024).toFixed(1)} KB</p></div><Button type="button" variant="ghost" size="icon" onClick={() => { setEmlFile(null); setEmlText(''); }} aria-label="Remove selected file" className="text-slate-500"><X /></Button></div>}
              </div>
            )}

            {error && <Alert id="analysis-error" className="border-rose-500/30 bg-rose-500/10 text-rose-200"><AlertTitle>Unable to analyze</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
              <div className="flex gap-2">
                {mode === 'raw_email' && <Button type="button" variant="ghost" size="sm" onClick={() => { setRawEmail(MOCK_EXAMPLE_EMAIL); setResult(null); }} className="text-slate-400 hover:bg-slate-800 hover:text-white">Load example</Button>}
                <Button type="button" variant="ghost" size="sm" onClick={handleClear} disabled={isLoading} className="text-slate-400 hover:bg-slate-800 hover:text-white"><Trash2 />Clear</Button>
              </div>
              <Button type="button" onClick={handleAnalyze} disabled={isLoading || !canAnalyze} className="bg-blue-600 text-white hover:bg-blue-500">{isLoading ? <><Loader2 className="animate-spin" />Analyzing…</> : <><Send />Analyze email</>}</Button>
            </div>
          </CardContent>
        </Card>

        <div className="xl:col-span-5">
          <AnalysisResults result={result} isLoading={isLoading} />
        </div>
      </div>
    </div>
  );
}
