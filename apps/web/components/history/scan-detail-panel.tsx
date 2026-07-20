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
  onDelete?: (id: string) => void;
}

const verdictStyles = {
  safe: { text: 'text-success', border: 'border-success/30', badge: 'border-success/30 bg-success/10 text-success', progress: '[&>div]:bg-success', icon: CheckCircle2 },
  suspicious: { text: 'text-warning', border: 'border-warning/30', badge: 'border-warning/30 bg-warning/10 text-warning', progress: '[&>div]:bg-warning', icon: AlertTriangle },
  phishing: { text: 'text-danger', border: 'border-danger/30', badge: 'border-danger/30 bg-danger/10 text-danger', progress: '[&>div]:bg-danger', icon: ShieldAlert },
};

const severityStyles = {
  low: 'border-primary/30 bg-primary/10 text-primary',
  medium: 'border-warning/30 bg-warning/10 text-warning',
  high: 'border-danger/30 bg-danger/10 text-danger',
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
  return <p className="text-sm leading-6 text-foreground0">{label} was not retained for this legacy scan record.</p>;
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
    <div className="fixed inset-0 z-50 bg-background/75 backdrop-blur-sm" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby="scan-detail-title" className="ml-auto h-full w-full max-w-4xl overflow-y-auto border-l border-border bg-background shadow-2xl shadow-black/50">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-border bg-background/95 px-5 py-4 backdrop-blur sm:px-7">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Scan investigation</p>
            <h2 id="scan-detail-title" className="mt-1 truncate text-lg font-semibold text-foreground">{scan.subject}</h2>
            <p className="mt-1 flex items-center gap-2 text-xs text-foreground0"><Clock size={13} aria-hidden="true" />{formatTimestamp(scan.timestamp)}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {onDelete && <Button type="button" variant="ghost" size="icon" onClick={() => onDelete(scan.id)} aria-label="Delete this scan" className="text-foreground0 hover:bg-danger/10 hover:text-danger"><Trash2 aria-hidden="true" /></Button>}
            <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close scan details" className="text-muted-foreground hover:bg-surface-muted hover:text-foreground"><X aria-hidden="true" /></Button>
          </div>
        </header>

        <div className="space-y-6 p-5 sm:p-7">
          {!details && (
            <div className="flex gap-3 rounded-lg border border-primary/20 bg-primary/5 p-4 text-sm leading-6 text-primary">
              <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              This record predates detailed history storage. Its verdict, score, confidence, counts, and indicators remain available.
            </div>
          )}

          <Card className={cn('border bg-surface/90', style.border)}>
            <CardHeader className="pb-4">
              <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                <div className="flex items-center gap-3">
                  <VerdictIcon className={style.text} aria-hidden="true" />
                  <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-foreground0">Final verdict</p><CardTitle className={cn('mt-1 text-2xl capitalize', style.text)}>{scan.classification}</CardTitle></div>
                </div>
                <Badge variant="outline" className={style.badge}>{scan.riskScore >= 70 ? 'Immediate action' : scan.riskScore >= 30 ? 'Review advised' : 'Low concern'}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div><div className="mb-2 flex items-end justify-between"><span className="text-sm text-muted-foreground">Risk score</span><span className="text-3xl font-semibold tabular-nums text-foreground">{scan.riskScore}<span className="text-sm font-normal text-foreground0">/100</span></span></div><Progress value={scan.riskScore} className={cn('h-2 bg-surface-muted', style.progress)} aria-label={`Risk score ${scan.riskScore} out of 100`} /></div>
              <Separator className="bg-surface-muted" />
              <div><p className="text-xs text-foreground0">Confidence</p><p className="mt-1 text-lg font-semibold text-foreground">{Math.round(scan.confidence * 100)}%</p></div>
            </CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-border bg-surface/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><Mail className="h-4 w-4 text-foreground0" aria-hidden="true" />Email metadata</CardTitle></CardHeader>
              <CardContent><dl className="space-y-3 text-sm">{[
                ['Subject', scan.subject],
                ['Sender', scan.sender],
                ['Reply-To', details?.replyTo ?? 'Not available'],
                ['Recipients', details?.recipients.join(', ') || 'Not available'],
                ['CC', details?.cc.join(', ') || 'None'],
                ['Message date', details?.messageDate ?? 'Not available'],
                ['Message-ID', details?.messageId ?? 'Not available'],
                ['Analyzed', formatTimestamp(scan.timestamp)],
              ].map(([label, value]) => <div key={label} className="grid grid-cols-[100px_1fr] gap-3"><dt className="text-foreground0">{label}</dt><dd className="break-all text-muted-foreground">{value}</dd></div>)}</dl></CardContent>
            </Card>

            <Card className="border-border bg-surface/80">
              <CardHeader><CardTitle className="text-base text-foreground">Recommendations</CardTitle></CardHeader>
              <CardContent>{details ? (details.recommendations.length ? <ol className="space-y-3">{details.recommendations.map((recommendation, index) => <li key={`${recommendation}-${index}`} className="flex gap-3 text-sm leading-6 text-muted-foreground"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-muted text-[10px] text-muted-foreground">{index + 1}</span>{recommendation}</li>)}</ol> : <p className="text-sm text-foreground0">No recommendations recorded.</p>) : <UnavailableDetails label="Recommendations" />}</CardContent>
            </Card>
          </div>

          <Card className="border-border bg-surface/80">
            <CardHeader><CardTitle className="text-base text-foreground">Detected indicators</CardTitle></CardHeader>
            <CardContent>{scan.indicators.length ? <div className="space-y-4">{scan.indicators.map((indicator, index) => <div key={`${indicator.code}-${index}`}>{index > 0 && <Separator className="mb-4 bg-surface-muted" />}<div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-foreground">{indicator.title}</p>{indicator.description && <p className="mt-1 text-sm leading-5 text-muted-foreground">{indicator.description}</p>}</div><Badge variant="outline" className={cn('shrink-0 capitalize', severityStyles[indicator.severity])}>{indicator.severity} · +{indicator.score}</Badge></div><div className="mt-2 rounded-md border border-border bg-background/60 px-3 py-2 text-xs"><span className="text-foreground0">Found in {indicator.category}: </span><span className="break-words text-muted-foreground">{indicator.evidence || 'Pattern-based detection'}</span></div></div>)}</div> : <p className="text-sm text-foreground0">No indicators detected.</p>}</CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-border bg-surface/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><LinkIcon className="h-4 w-4 text-foreground0" aria-hidden="true" />URLs <Badge variant="outline" className="ml-auto border-input text-muted-foreground">{scan.extractedUrlCount}</Badge></CardTitle></CardHeader>
              <CardContent>{details ? (details.urls.length ? <ul className="space-y-2">{details.urls.map((url, index) => <li key={`${url}-${index}`} className="break-all rounded-md border border-border bg-background/60 p-3 font-mono text-xs text-muted-foreground">{url}</li>)}</ul> : <p className="text-sm text-foreground0">No URLs extracted.</p>) : <UnavailableDetails label="URL values" />}</CardContent>
            </Card>

            <Card className="border-border bg-surface/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><Paperclip className="h-4 w-4 text-foreground0" aria-hidden="true" />Attachments <Badge variant="outline" className="ml-auto border-input text-muted-foreground">{scan.attachmentCount}</Badge></CardTitle></CardHeader>
              <CardContent className={details?.attachments.length ? 'px-0' : undefined}>{details ? (details.attachments.length ? <Table><TableHeader><TableRow className="border-border"><TableHead className="text-foreground0">File</TableHead><TableHead className="text-foreground0">Type</TableHead><TableHead className="text-right text-foreground0">Size</TableHead></TableRow></TableHeader><TableBody>{details.attachments.map((attachment, index) => <TableRow key={`${attachment.filename}-${index}`} className="border-border"><TableCell className="max-w-44 truncate text-muted-foreground">{attachment.filename || 'Unnamed'}</TableCell><TableCell className="text-xs text-muted-foreground">{attachment.content_type || 'Unknown'}</TableCell><TableCell className="text-right text-xs tabular-nums text-muted-foreground">{formatFileSize(attachment.size_bytes)}</TableCell></TableRow>)}</TableBody></Table> : <p className="text-sm text-foreground0">No attachment metadata found.</p>) : <UnavailableDetails label="Attachment metadata" />}</CardContent>
            </Card>
          </div>
        </div>
      </section>
    </div>
  );
}
