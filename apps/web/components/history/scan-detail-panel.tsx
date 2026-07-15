'use client';

import { useEffect } from 'react';
import { AlertTriangle, CheckCircle2, Clock, Info, Link as LinkIcon, Mail, Paperclip, ShieldAlert, Trash2, X } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface ScanDetailPanelProps {
  scan: ScanRecord;
  onClose: () => void;
  onDelete: (id: string) => void;
}

const verdictStyles = {
  safe: { text: 'text-emerald-300', border: 'border-emerald-500/30', badge: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300', progress: '[&>div]:bg-emerald-500', icon: CheckCircle2 },
  suspicious: { text: 'text-amber-300', border: 'border-amber-500/30', badge: 'border-amber-500/30 bg-amber-500/10 text-amber-300', progress: '[&>div]:bg-amber-500', icon: AlertTriangle },
  phishing: { text: 'text-rose-300', border: 'border-rose-500/30', badge: 'border-rose-500/30 bg-rose-500/10 text-rose-300', progress: '[&>div]:bg-rose-500', icon: ShieldAlert },
};

const severityStyles = {
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  high: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
};

function formatTimestamp(timestamp: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'full', timeStyle: 'medium' }).format(new Date(timestamp));
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function UnavailableDetails({ label }: { label: string }) {
  return <p className="text-sm leading-6 text-slate-500">{label} was not retained for this legacy scan record.</p>;
}

export function ScanDetailPanel({ scan, onClose, onDelete }: ScanDetailPanelProps) {
  const style = verdictStyles[scan.classification];
  const VerdictIcon = style.icon;
  const details = scan.details;

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-sm" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby="scan-detail-title" className="ml-auto h-full w-full max-w-4xl overflow-y-auto border-l border-slate-800 bg-slate-950 shadow-2xl shadow-black/50">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-950/95 px-5 py-4 backdrop-blur sm:px-7">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-blue-400">Scan investigation</p>
            <h2 id="scan-detail-title" className="mt-1 truncate text-lg font-semibold text-slate-100">{scan.subject}</h2>
            <p className="mt-1 flex items-center gap-2 text-xs text-slate-500"><Clock size={13} aria-hidden="true" />{formatTimestamp(scan.timestamp)}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button type="button" variant="ghost" size="icon" onClick={() => onDelete(scan.id)} aria-label="Delete this scan" className="text-slate-500 hover:bg-rose-500/10 hover:text-rose-300"><Trash2 aria-hidden="true" /></Button>
            <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close scan details" className="text-slate-400 hover:bg-slate-800 hover:text-white"><X aria-hidden="true" /></Button>
          </div>
        </header>

        <div className="space-y-6 p-5 sm:p-7">
          {!details && (
            <div className="flex gap-3 rounded-lg border border-sky-500/20 bg-sky-500/5 p-4 text-sm leading-6 text-sky-200">
              <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              This record predates detailed history storage. Its verdict, score, confidence, counts, and indicators remain available.
            </div>
          )}

          <Card className={cn('border bg-slate-900/90', style.border)}>
            <CardHeader className="pb-4">
              <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                <div className="flex items-center gap-3">
                  <VerdictIcon className={style.text} aria-hidden="true" />
                  <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Final verdict</p><CardTitle className={cn('mt-1 text-2xl capitalize', style.text)}>{scan.classification}</CardTitle></div>
                </div>
                <Badge variant="outline" className={style.badge}>{scan.riskScore >= 70 ? 'Immediate action' : scan.riskScore >= 30 ? 'Review advised' : 'Low concern'}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div><div className="mb-2 flex items-end justify-between"><span className="text-sm text-slate-400">Risk score</span><span className="text-3xl font-semibold tabular-nums text-slate-100">{scan.riskScore}<span className="text-sm font-normal text-slate-500">/100</span></span></div><Progress value={scan.riskScore} className={cn('h-2 bg-slate-800', style.progress)} aria-label={`Risk score ${scan.riskScore} out of 100`} /></div>
              <Separator className="bg-slate-800" />
              <div><p className="text-xs text-slate-500">Confidence</p><p className="mt-1 text-lg font-semibold text-slate-200">{Math.round(scan.confidence * 100)}%</p></div>
            </CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-slate-800 bg-slate-900/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Mail className="h-4 w-4 text-slate-500" aria-hidden="true" />Email metadata</CardTitle></CardHeader>
              <CardContent><dl className="space-y-3 text-sm">{[
                ['Subject', scan.subject],
                ['Sender', scan.sender],
                ['Reply-To', details?.replyTo ?? 'Not available'],
                ['Recipients', details?.recipients.join(', ') || 'Not available'],
                ['CC', details?.cc.join(', ') || 'None'],
                ['Message date', details?.messageDate ?? 'Not available'],
                ['Message-ID', details?.messageId ?? 'Not available'],
                ['Analyzed', formatTimestamp(scan.timestamp)],
              ].map(([label, value]) => <div key={label} className="grid grid-cols-[100px_1fr] gap-3"><dt className="text-slate-500">{label}</dt><dd className="break-all text-slate-300">{value}</dd></div>)}</dl></CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-900/80">
              <CardHeader><CardTitle className="text-base text-slate-100">Recommendations</CardTitle></CardHeader>
              <CardContent>{details ? (details.recommendations.length ? <ol className="space-y-3">{details.recommendations.map((recommendation, index) => <li key={`${recommendation}-${index}`} className="flex gap-3 text-sm leading-6 text-slate-300"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 text-[10px] text-slate-400">{index + 1}</span>{recommendation}</li>)}</ol> : <p className="text-sm text-slate-500">No recommendations recorded.</p>) : <UnavailableDetails label="Recommendations" />}</CardContent>
            </Card>
          </div>

          <Card className="border-slate-800 bg-slate-900/80">
            <CardHeader><CardTitle className="text-base text-slate-100">Detected indicators</CardTitle></CardHeader>
            <CardContent>{scan.indicators.length ? <div className="space-y-4">{scan.indicators.map((indicator, index) => <div key={`${indicator.code}-${index}`}>{index > 0 && <Separator className="mb-4 bg-slate-800" />}<div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-slate-200">{indicator.title}</p>{indicator.description && <p className="mt-1 text-sm leading-5 text-slate-400">{indicator.description}</p>}</div><Badge variant="outline" className={cn('shrink-0 capitalize', severityStyles[indicator.severity])}>{indicator.severity} · +{indicator.score}</Badge></div><div className="mt-2 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs"><span className="text-slate-500">Found in {indicator.category}: </span><span className="break-words text-slate-300">{indicator.evidence || 'Pattern-based detection'}</span></div></div>)}</div> : <p className="text-sm text-slate-500">No indicators detected.</p>}</CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-slate-800 bg-slate-900/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><LinkIcon className="h-4 w-4 text-slate-500" aria-hidden="true" />URLs <Badge variant="outline" className="ml-auto border-slate-700 text-slate-400">{scan.extractedUrlCount}</Badge></CardTitle></CardHeader>
              <CardContent>{details ? (details.urls.length ? <ul className="space-y-2">{details.urls.map((url, index) => <li key={`${url}-${index}`} className="break-all rounded-md border border-slate-800 bg-slate-950/60 p-3 font-mono text-xs text-slate-300">{url}</li>)}</ul> : <p className="text-sm text-slate-500">No URLs extracted.</p>) : <UnavailableDetails label="URL values" />}</CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-900/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-slate-100"><Paperclip className="h-4 w-4 text-slate-500" aria-hidden="true" />Attachments <Badge variant="outline" className="ml-auto border-slate-700 text-slate-400">{scan.attachmentCount}</Badge></CardTitle></CardHeader>
              <CardContent className={details?.attachments.length ? 'px-0' : undefined}>{details ? (details.attachments.length ? <Table><TableHeader><TableRow className="border-slate-800"><TableHead className="text-slate-500">File</TableHead><TableHead className="text-slate-500">Type</TableHead><TableHead className="text-right text-slate-500">Size</TableHead></TableRow></TableHeader><TableBody>{details.attachments.map((attachment, index) => <TableRow key={`${attachment.filename}-${index}`} className="border-slate-800"><TableCell className="max-w-44 truncate text-slate-300">{attachment.filename || 'Unnamed'}</TableCell><TableCell className="text-xs text-slate-400">{attachment.content_type || 'Unknown'}</TableCell><TableCell className="text-right text-xs tabular-nums text-slate-400">{formatFileSize(attachment.size_bytes)}</TableCell></TableRow>)}</TableBody></Table> : <p className="text-sm text-slate-500">No attachment metadata found.</p>) : <UnavailableDetails label="Attachment metadata" />}</CardContent>
            </Card>
          </div>
        </div>
      </section>
    </div>
  );
}
