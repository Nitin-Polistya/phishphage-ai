'use client';

import { useEffect, useMemo, useState } from 'react';
import { LockKeyhole, RefreshCw, Send, ShieldCheck } from 'lucide-react';

import { ApiError, fetchDatasetReviewStatus, previewDatasetReview, requestGeminiSuggestion, saveDatasetHumanReview } from '@/lib/api';
import type { DatasetReviewPreview, DatasetReviewStatus, GeminiSuggestion, ReviewLabel, ReviewMode } from '@/types/dataset-review';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

const labels: ReviewLabel[] = ['safe', 'suspicious', 'phishing'];

function errorMessage(error: unknown) {
  return error instanceof ApiError ? error.message : 'The local review request failed safely.';
}

export function DatasetReviewWorkspace() {
  const [status, setStatus] = useState<DatasetReviewStatus | null>(null);
  const [statusError, setStatusError] = useState('');
  const [token, setToken] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [sampleId, setSampleId] = useState('synthetic-review-001');
  const [subject, setSubject] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [senderDomain, setSenderDomain] = useState('example.com');
  const [replyToDomain, setReplyToDomain] = useState('');
  const [authSummary, setAuthSummary] = useState('spf=pass; dkim=pass; dmarc=pass');
  const [body, setBody] = useState('');
  const [urlDomains, setUrlDomains] = useState('example.com');
  const [urlFlags, setUrlFlags] = useState('');
  const [attachmentExtension, setAttachmentExtension] = useState('');
  const [attachmentMime, setAttachmentMime] = useState('');
  const [preview, setPreview] = useState<DatasetReviewPreview | null>(null);
  const [reviewMode, setReviewMode] = useState<ReviewMode>('independent');
  const [preliminaryLabel, setPreliminaryLabel] = useState<ReviewLabel>('suspicious');
  const [preliminaryNotes, setPreliminaryNotes] = useState('');
  const [consent, setConsent] = useState(false);
  const [suggestion, setSuggestion] = useState<GeminiSuggestion | null>(null);
  const [finalLabel, setFinalLabel] = useState<ReviewLabel>('suspicious');
  const [finalConfidence, setFinalConfidence] = useState('0.5');
  const [finalNotes, setFinalNotes] = useState('');
  const [changeReason, setChangeReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    setSessionId(globalThis.crypto?.randomUUID?.() || `tab-${Date.now()}`);
    void fetchDatasetReviewStatus().then(setStatus).catch((error: unknown) => setStatusError(errorMessage(error)));
  }, []);

  const evidence = useMemo(() => ({
    sample_id: sampleId,
    subject,
    display_name: displayName,
    sender_domain: senderDomain,
    reply_to_domain: replyToDomain,
    authentication_summary: authSummary.split(';').map((item) => item.trim()).filter(Boolean),
    body_excerpt: body,
    visible_html_text: '',
    url_domains: urlDomains.split(',').map((item) => item.trim()).filter(Boolean),
    url_structural_flags: urlFlags.split(',').map((item) => item.trim()).filter(Boolean),
    attachment_extension: attachmentExtension,
    attachment_mime: attachmentMime,
    parser_evidence: [],
    candidate_campaign_category: '',
  }), [attachmentExtension, attachmentMime, authSummary, body, displayName, replyToDomain, sampleId, senderDomain, subject, urlDomains, urlFlags]);

  const lockWorkspace = () => {
    setToken('');
    setPreview(null);
    setSuggestion(null);
    setConsent(false);
    setMessage('Workspace locked. The administrative token remains only in this tab memory.');
  };

  const createPreview = async () => {
    if (!token) return setMessage('Enter the local administrative token to prepare a preview.');
    setBusy(true); setMessage(''); setSuggestion(null); setConsent(false);
    try { setPreview(await previewDatasetReview(evidence, token)); }
    catch (error) { setPreview(null); setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const sendToGemini = async () => {
    if (!preview || !token || !sessionId) return setMessage('Prepare a fresh sanitized preview first.');
    if (!consent) return setMessage('Review the preview and check the specific-payload consent box first.');
    if (reviewMode === 'independent' && !preliminaryNotes.trim()) return setMessage('Independent review requires preliminary notes before the suggestion is shown.');
    setBusy(true); setMessage('');
    try {
      const result = await requestGeminiSuggestion(preview.payload, token, sessionId, { consent, reviewMode, reviewerAlias: 'reviewer-1', preliminaryLabel, preliminaryNotes });
      setSuggestion(result.suggestion);
      setFinalLabel(result.suggestion.suggested_label === 'unable_to_determine' ? 'suspicious' : result.suggestion.suggested_label);
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const saveFinalReview = async () => {
    if (!preview || !token || !finalNotes.trim()) return setMessage('A final human label and note are required.');
    setBusy(true); setMessage('');
    try {
      await saveDatasetHumanReview({ sample_id: preview.payload.sample_id, reviewer_id: 'reviewer-1', reviewer_role: 'reviewer_1', review_mode: suggestion ? reviewMode : 'independent', label: finalLabel, confidence: Number(finalConfidence), notes: finalNotes, preliminary_label: preliminaryLabel, preliminary_notes: preliminaryNotes || 'Human preliminary review recorded locally.', change_reason: suggestion ? changeReason || 'Human confirmed or changed the advisory suggestion.' : undefined, content_hash: preview.payload.sanitized_payload_hash }, token);
      setMessage('Human review saved. Gemini did not set the benchmark label.');
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div><p className="text-sm font-semibold uppercase tracking-[0.18em] text-primary">Internal curation</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Dataset review workspace</h1><p className="mt-2 max-w-3xl text-sm text-muted-foreground">A local, human-in-the-loop review surface for gold-standard evidence. Gemini can advise; only a human can create benchmark truth.</p></div>
        <div className="flex items-center gap-2"><Badge variant="outline">{status?.enabled ? 'Enabled locally' : 'Disabled by default'}</Badge>{token && <Button variant="outline" onClick={lockWorkspace}><LockKeyhole className="mr-2 h-4 w-4" />Lock</Button>}</div>
      </div>

      {statusError && <Alert variant="destructive"><AlertTitle>Review service unavailable</AlertTitle><AlertDescription>{statusError}</AlertDescription></Alert>}
      {!status?.enabled && !statusError && <Alert><ShieldCheck className="h-4 w-4" /><AlertTitle>Dataset review is inactive</AlertTitle><AlertDescription>This route exposes no active review controls while DATASET_REVIEW_ENABLED=false. Enable it only on a local development API with a separate admin token.</AlertDescription></Alert>}
      {status?.enabled && <>
        <Alert><ShieldCheck className="h-4 w-4" /><AlertTitle>Privacy boundary</AlertTitle><AlertDescription>Only this sanitized preview can be sent to an external AI provider. Do not submit personal, confidential, credential-bearing, live malicious, or attachment content. Gemini is advisory, may process submitted data under free-tier terms, and never counts as reviewer two.</AlertDescription></Alert>

        <Card><CardHeader><CardTitle className="flex items-center justify-between">1. Prepare sanitized evidence <Button variant="outline" size="sm" onClick={() => void fetchDatasetReviewStatus().then(setStatus)}><RefreshCw className="mr-2 h-4 w-4" />Refresh status</Button></CardTitle></CardHeader><CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2"><div><Label htmlFor="review-token">Local admin token (memory only)</Label><Input id="review-token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} /></div><div><Label htmlFor="sample-id">Stable sample ID</Label><Input id="sample-id" value={sampleId} onChange={(event) => { setSampleId(event.target.value); setPreview(null); }} /></div></div>
          <div className="grid gap-4 sm:grid-cols-2"><div><Label htmlFor="subject">Sanitized subject</Label><Input id="subject" maxLength={300} value={subject} onChange={(event) => setSubject(event.target.value)} /></div><div><Label htmlFor="display-name">Display name (optional)</Label><Input id="display-name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></div></div>
          <div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="sender-domain">Sender domain</Label><Input id="sender-domain" value={senderDomain} onChange={(event) => setSenderDomain(event.target.value)} /></div><div><Label htmlFor="reply-domain">Reply-To domain</Label><Input id="reply-domain" value={replyToDomain} onChange={(event) => setReplyToDomain(event.target.value)} /></div><div><Label htmlFor="auth">Authentication summary</Label><Input id="auth" value={authSummary} onChange={(event) => setAuthSummary(event.target.value)} /></div></div>
          <div><Label htmlFor="body">Sanitized body excerpt</Label><Textarea id="body" maxLength={8000} rows={8} value={body} onChange={(event) => setBody(event.target.value)} placeholder="Plain text evidence only; do not paste raw .eml content." /></div>
          <div className="grid gap-4 sm:grid-cols-4"><div><Label htmlFor="urls">URL domains only</Label><Input id="urls" value={urlDomains} onChange={(event) => setUrlDomains(event.target.value)} /></div><div><Label htmlFor="flags">URL structural flags</Label><Input id="flags" value={urlFlags} onChange={(event) => setUrlFlags(event.target.value)} /></div><div><Label htmlFor="extension">Attachment extension</Label><Input id="extension" value={attachmentExtension} onChange={(event) => setAttachmentExtension(event.target.value)} /></div><div><Label htmlFor="mime">Attachment MIME</Label><Input id="mime" value={attachmentMime} onChange={(event) => setAttachmentMime(event.target.value)} /></div></div>
          <Button onClick={() => void createPreview()} disabled={busy || !token}><RefreshCw className="mr-2 h-4 w-4" />Sanitize and preview</Button>
        </CardContent></Card>

        {preview && <Card><CardHeader><CardTitle>2. Human-approved preview</CardTitle></CardHeader><CardContent className="space-y-4 text-sm"><p className="text-muted-foreground">Exactly this payload is bound to consent. Any sample, evidence, model, or prompt change invalidates the hash.</p><div className="grid gap-3 rounded-lg bg-surface-muted p-4 sm:grid-cols-2"><div><span className="text-muted-foreground">Subject</span><p className="font-medium">{preview.payload.subject || '—'}</p></div><div><span className="text-muted-foreground">Domains</span><p className="font-medium">{[preview.payload.sender_domain, preview.payload.reply_to_domain, ...preview.payload.url_domains].filter(Boolean).join(', ') || '—'}</p></div><div><span className="text-muted-foreground">Authentication</span><p>{preview.payload.authentication_summary.join('; ') || '—'}</p></div><div><span className="text-muted-foreground">Attachment metadata</span><p>{preview.payload.attachment_extension || 'none'} {preview.payload.attachment_mime && `· ${preview.payload.attachment_mime}`}</p></div><div className="sm:col-span-2"><span className="text-muted-foreground">Body preview</span><p className="whitespace-pre-wrap break-words">{preview.payload.body_excerpt || '—'}</p></div></div><p className="break-all font-mono text-xs text-muted-foreground">{preview.payload_bytes} bytes · SHA-256 {preview.payload_hash} · model {preview.payload.model_name} · prompt {preview.payload.prompt_version}</p><p>{preview.notice}</p><label className="flex items-start gap-3 rounded-lg border border-border p-3"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} className="mt-1" /><span>I reviewed the sanitized preview and consent to sending this specific payload to Gemini for an advisory suggestion.</span></label></CardContent></Card>}

        {preview && <Card><CardHeader><CardTitle>3. Review mode and suggestion</CardTitle></CardHeader><CardContent className="space-y-4"><div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="mode">Review mode</Label><select id="mode" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={reviewMode} onChange={(event) => setReviewMode(event.target.value as ReviewMode)}><option value="independent">Independent (default)</option><option value="ai_assisted">AI-assisted</option></select></div><div><Label htmlFor="preliminary">Preliminary human label</Label><select id="preliminary" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={preliminaryLabel} onChange={(event) => setPreliminaryLabel(event.target.value as ReviewLabel)}>{labels.map((label) => <option key={label} value={label}>{label}</option>)}</select></div><div><Label htmlFor="preliminary-notes">Preliminary notes</Label><Input id="preliminary-notes" value={preliminaryNotes} onChange={(event) => setPreliminaryNotes(event.target.value)} placeholder="Required in independent mode" /></div></div><Button onClick={() => void sendToGemini()} disabled={busy || !consent || !status?.gemini_enabled}><Send className="mr-2 h-4 w-4" />Send sanitized review data to Gemini</Button>{suggestion && <div className="space-y-3 rounded-lg border border-border p-4"><div className="flex flex-wrap items-center gap-2"><Badge>{suggestion.suggested_label}</Badge><Badge variant="outline">confidence {suggestion.confidence.toFixed(2)}</Badge><span className="text-xs text-muted-foreground">Advisory suggestion · {suggestion.model_name}</span></div><p>{suggestion.summary}</p><div><p className="font-semibold">Evidence</p><ul className="mt-1 list-disc space-y-1 pl-5 text-sm">{suggestion.evidence.map((item) => <li key={item.title}><span className="font-medium">{item.title}:</span> {item.explanation}</li>)}</ul></div></div>}</CardContent></Card>}

        {preview && <Card><CardHeader><CardTitle>4. Human final decision</CardTitle></CardHeader><CardContent className="space-y-4"><p className="text-sm text-muted-foreground">Gemini suggestions never become expected_class, final_human_label, adjudicated_label, or benchmark truth.</p><div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="final-label">Final human label</Label><select id="final-label" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={finalLabel} onChange={(event) => setFinalLabel(event.target.value as ReviewLabel)}>{labels.map((label) => <option key={label} value={label}>{label}</option>)}</select></div><div><Label htmlFor="final-confidence">Confidence (0–1)</Label><Input id="final-confidence" type="number" min="0" max="1" step="0.01" value={finalConfidence} onChange={(event) => setFinalConfidence(event.target.value)} /></div><div><Label htmlFor="change-reason">Change reason if AI influenced</Label><Input id="change-reason" value={changeReason} onChange={(event) => setChangeReason(event.target.value)} /></div></div><div><Label htmlFor="final-notes">Final human notes</Label><Textarea id="final-notes" rows={4} value={finalNotes} onChange={(event) => setFinalNotes(event.target.value)} /></div><Button onClick={() => void saveFinalReview()} disabled={busy || !finalNotes.trim()}>Save human review</Button></CardContent></Card>}
      </>}
      {message && <Alert><AlertDescription>{message}</AlertDescription></Alert>}
    </div>
  );
}
