'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { LockKeyhole, RefreshCw, Send, ShieldCheck } from 'lucide-react';

import { ApiError, createGoldDatasetReview, exportGoldDataset, fetchDatasetReviewStatus, fetchGoldDatasetDashboard, previewDatasetReview, requestGeminiSuggestion, saveDatasetHumanReview, transitionGoldDatasetReview } from '@/lib/api';
import { toDatasetReviewServiceState, type DatasetReviewServiceState } from '@/lib/dataset-review-status';
import type { DatasetReviewPreview, DatasetReviewStatus, GeminiSuggestion, GoldDatasetDashboard, ReviewLabel, ReviewMode } from '@/types/dataset-review';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { BatchReviewQueue } from '@/components/dataset-review/batch-review-queue';

const labels: ReviewLabel[] = ['safe', 'suspicious', 'phishing'];

function errorMessage(error: unknown) {
  return error instanceof ApiError ? error.message : 'The local review request failed safely.';
}

export function DatasetReviewWorkspace() {
  const [serviceState, setServiceState] = useState<DatasetReviewServiceState>({ kind: 'loading' });
  const statusRequestId = useRef(0);
  const [dashboard, setDashboard] = useState<GoldDatasetDashboard | null>(null);
  const [token, setToken] = useState('');
  const [reviewerName, setReviewerName] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [sampleId, setSampleId] = useState('synthetic-review-001');
  const [sourceDataset, setSourceDataset] = useState('local-manual-review');
  const [sourceIdentifier, setSourceIdentifier] = useState('local-review-workspace');
  const [campaignIdentifier, setCampaignIdentifier] = useState('campaign-undetermined');
  const [language, setLanguage] = useState('und');
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
  const [acceptGeminiRecommendation, setAcceptGeminiRecommendation] = useState(false);
  const [finalLabel, setFinalLabel] = useState<ReviewLabel>('suspicious');
  const [labelQuality, setLabelQuality] = useState<'high' | 'medium' | 'low' | 'unresolved'>('medium');
  const [finalConfidence, setFinalConfidence] = useState('0.5');
  const [finalNotes, setFinalNotes] = useState('');
  const [changeReason, setChangeReason] = useState('');
  const [requiresSecondReview, setRequiresSecondReview] = useState(false);
  const [goldReviewId, setGoldReviewId] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  const refreshStatus = useCallback(async () => {
    const requestId = ++statusRequestId.current;
    setServiceState({ kind: 'loading' });
    try {
      const nextStatus = await fetchDatasetReviewStatus();
      if (requestId !== statusRequestId.current) return;
      setServiceState(toDatasetReviewServiceState(nextStatus));
    } catch (error) {
      if (requestId !== statusRequestId.current) return;
      setServiceState({ kind: 'unavailable', message: errorMessage(error) });
    }
  }, []);

  useEffect(() => {
    setSessionId(globalThis.crypto?.randomUUID?.() || `tab-${Date.now()}`);
    void refreshStatus();
  }, [refreshStatus]);

  const status: DatasetReviewStatus | null = serviceState.kind === 'enabled' || serviceState.kind === 'disabled' ? serviceState.status : null;

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
    setDashboard(null);
    setGoldReviewId('');
    setConsent(false);
    setMessage('Workspace locked. The administrative token remains only in this tab memory.');
  };

  const loadDashboard = async () => {
    if (!token) return setMessage('Enter the local administrative token to load gold-dataset metrics.');
    setBusy(true); setMessage('');
    try { setDashboard(await fetchGoldDatasetDashboard(token)); }
    catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const exportGold = async () => {
    if (!token) return setMessage('Enter the local administrative token to export the gold dataset.');
    setBusy(true); setMessage('');
    try { const result = await exportGoldDataset(token); setMessage(`Exported ${result.exported_samples} approved human-reviewed samples: ${result.files.join(', ')}`); }
    catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const createPreview = async () => {
    if (!token) return setMessage('Enter the local administrative token to prepare a preview.');
    setBusy(true); setMessage(''); setSuggestion(null); setConsent(false);
    try { setPreview(await previewDatasetReview(evidence, token)); }
    catch (error) { setPreview(null); setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const sendToGemini = async () => {
    if (!preview || !token || !sessionId || !reviewerName.trim()) return setMessage('Enter your human reviewer name and prepare a fresh sanitized preview first.');
    if (!consent) return setMessage('Review the preview and check the specific-payload consent box first.');
    if (reviewMode === 'independent' && !preliminaryNotes.trim()) return setMessage('Independent review requires preliminary notes before the suggestion is shown.');
    setBusy(true); setMessage('');
    try {
      const result = await requestGeminiSuggestion(preview.payload, token, sessionId, { consent, reviewMode, reviewerAlias: reviewerName.trim(), preliminaryLabel, preliminaryNotes });
      setSuggestion(result.suggestion);
      setAcceptGeminiRecommendation(false);
      setFinalLabel(result.suggestion.suggested_label === 'unable_to_determine' ? 'suspicious' : result.suggestion.suggested_label);
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const saveFinalReview = async () => {
    if (!preview || !token || !reviewerName.trim() || !finalNotes.trim() || !sourceDataset.trim() || !sourceIdentifier.trim() || !campaignIdentifier.trim() || !language.trim()) return setMessage('Reviewer, source dataset, source identifier, campaign identifier, language, final label, and note are required.');
    if (goldReviewId) return setMessage('This sample is already stored in the gold-dataset review workflow.');
    const confidence = Number(finalConfidence);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) return setMessage('Reviewer confidence must be between 0 and 1.');
    setBusy(true); setMessage('');
    try {
      await saveDatasetHumanReview({ sample_id: preview.payload.sample_id, reviewer_id: reviewerName.trim(), reviewer_role: 'reviewer_1', review_mode: suggestion ? reviewMode : 'independent', label: finalLabel, confidence, notes: finalNotes, preliminary_label: preliminaryLabel, preliminary_notes: preliminaryNotes || 'Human preliminary review recorded locally.', change_reason: suggestion ? changeReason || 'Human confirmed or changed the advisory suggestion.' : undefined, content_hash: preview.payload.sanitized_payload_hash }, token);
      const goldReview = await createGoldDatasetReview({
        sample_hash: preview.payload.sanitized_payload_hash,
        normalized_content_hash: preview.payload.sanitized_payload_hash,
        source_dataset: sourceDataset.trim(),
        source_sample_id: sampleId.trim(),
        source_identifier: sourceIdentifier.trim(),
        campaign_identifier: campaignIdentifier.trim(),
        reviewer_name: reviewerName.trim(),
        language: language.trim(),
        phishing_label: finalLabel,
        label_quality: labelQuality,
        reviewer_confidence: confidence,
        review_notes: finalNotes,
        gemini_recommendation: suggestion?.suggested_label ?? null,
        gemini_reasoning_summary: suggestion?.summary ?? null,
        accepted_gemini_recommendation: suggestion ? acceptGeminiRecommendation : false,
        requires_second_review: requiresSecondReview,
        state: 'pending',
      }, token);
      await transitionGoldDatasetReview(goldReview.review_id, token, 'reviewed', reviewerName.trim(), 'Primary human review completed.');
      setGoldReviewId(goldReview.review_id);
      setMessage(requiresSecondReview ? 'Human review saved and queued for a second human review. Gemini remains advisory.' : 'Human review saved in the gold-dataset workflow. Explicit approval is still required.');
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  const approveGoldReview = async () => {
    if (!goldReviewId || !token || !reviewerName.trim()) return setMessage('A stored gold review and human reviewer name are required.');
    if (requiresSecondReview) return setMessage('A second human decision is required before approval.');
    setBusy(true); setMessage('');
    try {
      await transitionGoldDatasetReview(goldReviewId, token, 'approved', reviewerName.trim(), 'Human approved the reviewed gold-dataset record.');
      setMessage('Gold-dataset record approved. Gemini did not set the benchmark label.');
      void loadDashboard();
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div><p className="text-sm font-semibold uppercase tracking-[0.18em] text-primary">Internal curation</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Dataset review workspace</h1><p className="mt-2 max-w-3xl text-sm text-muted-foreground">A local, human-in-the-loop review surface for gold-standard evidence. Gemini can advise; only a human can create benchmark truth.</p></div>
        <div className="flex items-center gap-2"><Badge variant="outline">{serviceState.kind === 'loading' ? 'Checking service' : serviceState.kind === 'unavailable' ? 'Service unavailable' : serviceState.kind === 'enabled' ? 'Enabled locally' : 'Disabled by backend'}</Badge>{token && <Button type="button" variant="outline" onClick={lockWorkspace}><LockKeyhole className="mr-2 h-4 w-4" />Lock</Button>}</div>
      </div>

      {serviceState.kind === 'loading' && <Alert><RefreshCw className="h-4 w-4" /><AlertTitle>Checking dataset review service</AlertTitle><AlertDescription>Reading the backend status before showing review controls.</AlertDescription></Alert>}
      {serviceState.kind === 'unavailable' && <Alert variant="destructive"><RefreshCw className="h-4 w-4" /><AlertTitle>Unable to reach dataset review service</AlertTitle><AlertDescription>{serviceState.message || 'Check that the local API is running, then retry.'} <Button type="button" variant="outline" size="sm" onClick={() => void refreshStatus()}>Retry status</Button></AlertDescription></Alert>}
      {serviceState.kind === 'disabled' && <Alert><ShieldCheck className="h-4 w-4" /><AlertTitle>Dataset review is disabled</AlertTitle><AlertDescription>The backend reports DATASET_REVIEW_ENABLED=false. Enable it only on a local development API with a separate admin token. <Button type="button" variant="outline" size="sm" onClick={() => void refreshStatus()}>Refresh status</Button></AlertDescription></Alert>}
      {serviceState.kind === 'enabled' && <>
        <Alert><ShieldCheck className="h-4 w-4" /><AlertTitle>Privacy boundary</AlertTitle><AlertDescription>Only this sanitized preview can be sent to an external AI provider. Do not submit personal, confidential, credential-bearing, live malicious, or attachment content. Gemini is advisory, may process submitted data under free-tier terms, and never counts as reviewer two.</AlertDescription></Alert>
         {(!serviceState.status.gemini_enabled || !serviceState.status.provider_ready) && <Alert><ShieldCheck className="h-4 w-4" /><AlertTitle>Gemini advisory review is unavailable</AlertTitle><AlertDescription>Human Dataset Review is enabled. Gemini remains optional and is currently disabled or not configured.</AlertDescription></Alert>}
         <BatchReviewQueue token={token} reviewerName={reviewerName} onMessage={(nextMessage) => setMessage(nextMessage)} />

        <Card><CardHeader><CardTitle className="flex items-center justify-between">Gold dataset quality dashboard <div className="flex gap-2"><Button variant="outline" size="sm" onClick={() => void loadDashboard()} disabled={busy || !token}><RefreshCw className="mr-2 h-4 w-4" />Load metrics</Button><Button variant="outline" size="sm" onClick={() => void exportGold()} disabled={busy || !token}>Export approved</Button></div></CardTitle></CardHeader><CardContent>{dashboard ? <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6"><div><p className="text-xs text-muted-foreground">Samples</p><p className="text-2xl font-bold">{dashboard.total_samples}</p></div><div><p className="text-xs text-muted-foreground">Completion</p><p className="text-2xl font-bold">{Math.round(dashboard.review_completion * 100)}%</p></div><div><p className="text-xs text-muted-foreground">Approved</p><p className="text-2xl font-bold">{dashboard.approved_samples}</p></div><div><p className="text-xs text-muted-foreground">Queue</p><p className="text-2xl font-bold">{Object.values(dashboard.review_queue).reduce((sum, count) => sum + count, 0)}</p></div><div><p className="text-xs text-muted-foreground">Second reviews</p><p className="text-2xl font-bold">{dashboard.second_review_count}</p></div><div><p className="text-xs text-muted-foreground">Agreement</p><p className="text-2xl font-bold">{dashboard.reviewer_agreement ? `${Math.round(dashboard.reviewer_agreement.agreement_rate * 100)}%` : '—'}</p></div><div className="sm:col-span-3 lg:col-span-6 flex flex-wrap gap-2 text-xs text-muted-foreground"><span>Labels: {Object.entries(dashboard.label_distribution).map(([label, count]) => `${label} ${count}`).join(' · ') || 'none'}</span><span>Languages: {Object.entries(dashboard.language_distribution).map(([language, count]) => `${language} ${count}`).join(' · ') || 'none'}</span><span>Sources: {Object.entries(dashboard.source_distribution).map(([source, count]) => `${source} ${count}`).join(' · ') || 'none'}</span></div></div> : <p className="text-sm text-muted-foreground">Metrics remain local and require an authorized reviewer session.</p>}</CardContent></Card>

        <Card><CardHeader><CardTitle className="flex items-center justify-between">1. Prepare sanitized evidence <Button type="button" variant="outline" size="sm" onClick={() => void refreshStatus()}><RefreshCw className="mr-2 h-4 w-4" />Refresh status</Button></CardTitle></CardHeader><CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="review-token">Local admin token (memory only)</Label><Input id="review-token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} /></div><div><Label htmlFor="reviewer-name">Human reviewer name</Label><Input id="reviewer-name" autoComplete="off" value={reviewerName} onChange={(event) => setReviewerName(event.target.value)} placeholder="Enter your own reviewer identity" /></div><div><Label htmlFor="sample-id">Stable sample ID</Label><Input id="sample-id" value={sampleId} onChange={(event) => { setSampleId(event.target.value); setPreview(null); }} /></div></div>
          <div className="grid gap-4 sm:grid-cols-4"><div><Label htmlFor="source-dataset">Source dataset</Label><Input id="source-dataset" value={sourceDataset} onChange={(event) => setSourceDataset(event.target.value)} /></div><div><Label htmlFor="source-identifier">Source identifier</Label><Input id="source-identifier" value={sourceIdentifier} onChange={(event) => setSourceIdentifier(event.target.value)} /></div><div><Label htmlFor="campaign-identifier">Campaign identifier</Label><Input id="campaign-identifier" value={campaignIdentifier} onChange={(event) => setCampaignIdentifier(event.target.value)} /></div><div><Label htmlFor="language">Language</Label><Input id="language" value={language} onChange={(event) => setLanguage(event.target.value)} /></div></div>
          <div className="grid gap-4 sm:grid-cols-2"><div><Label htmlFor="subject">Sanitized subject</Label><Input id="subject" maxLength={300} value={subject} onChange={(event) => setSubject(event.target.value)} /></div><div><Label htmlFor="display-name">Display name (optional)</Label><Input id="display-name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></div></div>
          <div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="sender-domain">Sender domain</Label><Input id="sender-domain" value={senderDomain} onChange={(event) => setSenderDomain(event.target.value)} /></div><div><Label htmlFor="reply-domain">Reply-To domain</Label><Input id="reply-domain" value={replyToDomain} onChange={(event) => setReplyToDomain(event.target.value)} /></div><div><Label htmlFor="auth">Authentication summary</Label><Input id="auth" value={authSummary} onChange={(event) => setAuthSummary(event.target.value)} /></div></div>
          <div><Label htmlFor="body">Sanitized body excerpt</Label><Textarea id="body" maxLength={8000} rows={8} value={body} onChange={(event) => setBody(event.target.value)} placeholder="Plain text evidence only; do not paste raw .eml content." /></div>
          <div className="grid gap-4 sm:grid-cols-4"><div><Label htmlFor="urls">URL domains only</Label><Input id="urls" value={urlDomains} onChange={(event) => setUrlDomains(event.target.value)} /></div><div><Label htmlFor="flags">URL structural flags</Label><Input id="flags" value={urlFlags} onChange={(event) => setUrlFlags(event.target.value)} /></div><div><Label htmlFor="extension">Attachment extension</Label><Input id="extension" value={attachmentExtension} onChange={(event) => setAttachmentExtension(event.target.value)} /></div><div><Label htmlFor="mime">Attachment MIME</Label><Input id="mime" value={attachmentMime} onChange={(event) => setAttachmentMime(event.target.value)} /></div></div>
          <Button type="button" onClick={() => void createPreview()} disabled={busy || !token}><RefreshCw className="mr-2 h-4 w-4" />Sanitize and preview</Button>
        </CardContent></Card>

        {preview && <Card><CardHeader><CardTitle>2. Human-approved preview</CardTitle></CardHeader><CardContent className="space-y-4 text-sm"><p className="text-muted-foreground">Exactly this payload is bound to consent. Any sample, evidence, model, or prompt change invalidates the hash.</p><div className="grid gap-3 rounded-lg bg-surface-muted p-4 sm:grid-cols-2"><div><span className="text-muted-foreground">Subject</span><p className="font-medium">{preview.payload.subject || '—'}</p></div><div><span className="text-muted-foreground">Domains</span><p className="font-medium">{[preview.payload.sender_domain, preview.payload.reply_to_domain, ...preview.payload.url_domains].filter(Boolean).join(', ') || '—'}</p></div><div><span className="text-muted-foreground">Authentication</span><p>{preview.payload.authentication_summary.join('; ') || '—'}</p></div><div><span className="text-muted-foreground">Attachment metadata</span><p>{preview.payload.attachment_extension || 'none'} {preview.payload.attachment_mime && `· ${preview.payload.attachment_mime}`}</p></div><div className="sm:col-span-2"><span className="text-muted-foreground">Body preview</span><p className="whitespace-pre-wrap break-words">{preview.payload.body_excerpt || '—'}</p></div></div><p className="break-all font-mono text-xs text-muted-foreground">{preview.payload_bytes} bytes · SHA-256 {preview.payload_hash} · model {preview.payload.model_name} · prompt {preview.payload.prompt_version}</p><p>{preview.notice}</p><label className="flex items-start gap-3 rounded-lg border border-border p-3"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} className="mt-1" /><span>I reviewed the sanitized preview and consent to sending this specific payload to Gemini for an advisory suggestion.</span></label></CardContent></Card>}

        {preview && <Card><CardHeader><CardTitle>3. Review mode and suggestion</CardTitle></CardHeader><CardContent className="space-y-4"><div className="grid gap-4 sm:grid-cols-3"><div><Label htmlFor="mode">Review mode</Label><select id="mode" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={reviewMode} onChange={(event) => setReviewMode(event.target.value as ReviewMode)}><option value="independent">Independent (default)</option><option value="ai_assisted">AI-assisted</option></select></div><div><Label htmlFor="preliminary">Preliminary human label</Label><select id="preliminary" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={preliminaryLabel} onChange={(event) => setPreliminaryLabel(event.target.value as ReviewLabel)}>{labels.map((label) => <option key={label} value={label}>{label}</option>)}</select></div><div><Label htmlFor="preliminary-notes">Preliminary notes</Label><Input id="preliminary-notes" value={preliminaryNotes} onChange={(event) => setPreliminaryNotes(event.target.value)} placeholder="Required in independent mode" /></div></div><Button onClick={() => void sendToGemini()} disabled={busy || !consent || !status?.gemini_enabled}><Send className="mr-2 h-4 w-4" />Send sanitized review data to Gemini</Button>{suggestion && <div className="space-y-3 rounded-lg border border-border p-4"><div className="flex flex-wrap items-center gap-2"><Badge>{suggestion.suggested_label}</Badge><Badge variant="outline">confidence {suggestion.confidence.toFixed(2)}</Badge><span className="text-xs text-muted-foreground">Advisory suggestion · {suggestion.model_name}</span></div><p>{suggestion.summary}</p><div><p className="font-semibold">Evidence</p><ul className="mt-1 list-disc space-y-1 pl-5 text-sm">{suggestion.evidence.map((item) => <li key={item.title}><span className="font-medium">{item.title}:</span> {item.explanation}</li>)}</ul></div><label className="flex items-start gap-3 rounded-lg border border-border p-3"><input type="checkbox" checked={acceptGeminiRecommendation} onChange={(event) => setAcceptGeminiRecommendation(event.target.checked)} className="mt-1" /><span>I accept this Gemini recommendation as advisory input; the final label below remains my human decision.</span></label></div>}</CardContent></Card>}

        {preview && <Card><CardHeader><CardTitle>4. Human final decision</CardTitle></CardHeader><CardContent className="space-y-4"><p className="text-sm text-muted-foreground">Gemini suggestions never become expected_class, final_human_label, adjudicated_label, or benchmark truth.</p><div className="grid gap-4 sm:grid-cols-4"><div><Label htmlFor="final-label">Final human label</Label><select id="final-label" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={finalLabel} onChange={(event) => setFinalLabel(event.target.value as ReviewLabel)}>{labels.map((label) => <option key={label} value={label}>{label}</option>)}</select></div><div><Label htmlFor="label-quality">Label quality</Label><select id="label-quality" className="mt-1 flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={labelQuality} onChange={(event) => setLabelQuality(event.target.value as typeof labelQuality)}><option value="high">high</option><option value="medium">medium</option><option value="low">low</option><option value="unresolved">unresolved</option></select></div><div><Label htmlFor="final-confidence">Confidence (0–1)</Label><Input id="final-confidence" type="number" min="0" max="1" step="0.01" value={finalConfidence} onChange={(event) => setFinalConfidence(event.target.value)} /></div><div><Label htmlFor="change-reason">Change reason if AI influenced</Label><Input id="change-reason" value={changeReason} onChange={(event) => setChangeReason(event.target.value)} /></div></div><div><Label htmlFor="final-notes">Final human notes</Label><Textarea id="final-notes" rows={4} value={finalNotes} onChange={(event) => setFinalNotes(event.target.value)} /></div><label className="flex items-start gap-3 rounded-lg border border-border p-3"><input type="checkbox" checked={requiresSecondReview} onChange={(event) => setRequiresSecondReview(event.target.checked)} className="mt-1" /><span>Require a second human review before this record can be approved.</span></label><div className="flex flex-wrap items-center gap-3"><Button onClick={() => void saveFinalReview()} disabled={busy || !finalNotes.trim() || Boolean(goldReviewId)}>Save human review to gold workflow</Button>{goldReviewId && <Button variant="outline" onClick={() => void approveGoldReview()} disabled={busy || requiresSecondReview}>Approve gold record</Button>}{goldReviewId && <span className="text-xs text-muted-foreground">Gold review {goldReviewId}</span>}</div></CardContent></Card>}
      </>}
      {message && <Alert><AlertDescription>{message}</AlertDescription></Alert>}
    </div>
  );
}
