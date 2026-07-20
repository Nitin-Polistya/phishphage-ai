'use client';

import { useEffect, useMemo } from 'react';
import { Clock, Download, FileText, Info, Link as LinkIcon, Mail, Paperclip, Printer, X } from 'lucide-react';

import { ClassificationBadge } from '@/components/scans/classification-badge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { createScanReport, formatReportDate, formatReportInputMode } from '@/lib/reports';
import { cn } from '@/lib/utils';
import type { ScanRecord } from '@/types';

interface ReportPreviewProps {
  scan: ScanRecord;
  onClose: () => void;
  onJson: () => void;
  onCsv: () => void;
  onPrint: () => void;
}

const severityStyles = {
  low: 'border-primary/30 bg-primary/10 text-primary',
  medium: 'border-warning/30 bg-warning/10 text-warning',
  high: 'border-danger/30 bg-danger/10 text-danger',
};

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function ReportPreview({ scan, onClose, onJson, onCsv, onPrint }: ReportPreviewProps) {
  const report = useMemo(() => createScanReport(scan), [scan]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 bg-background/80 p-3 backdrop-blur-sm sm:p-6" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby="report-preview-title" className="mx-auto flex h-full w-full max-w-6xl flex-col overflow-hidden rounded-lg border border-input bg-background shadow-2xl shadow-black/50">
        <header className="flex flex-col justify-between gap-4 border-b border-border bg-background px-5 py-4 sm:flex-row sm:items-center sm:px-7">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">PhishShield AI report preview</p>
            <h2 id="report-preview-title" className="mt-1 truncate text-lg font-semibold text-foreground">{report.subject}</h2>
            <p className="mt-1 flex items-center gap-2 text-xs text-foreground0"><Clock size={13} aria-hidden="true" />Generated {formatReportDate(report.report_generated_at)}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onJson} className="border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Download aria-hidden="true" />JSON</Button>
            <Button type="button" variant="outline" size="sm" onClick={onCsv} className="border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground"><Download aria-hidden="true" />CSV</Button>
            <Button type="button" size="sm" onClick={onPrint} className="bg-primary text-primary-foreground hover:bg-primary"><Printer aria-hidden="true" />Print / Save PDF</Button>
            <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close report preview" className="text-muted-foreground hover:bg-surface-muted hover:text-foreground"><X aria-hidden="true" /></Button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-5 sm:p-7">
          <div className="mx-auto max-w-5xl space-y-6">
            <div className="flex flex-col justify-between gap-5 border-b border-border pb-6 sm:flex-row sm:items-start">
              <div><p className="text-sm font-semibold text-primary">PhishShield AI</p><h3 className="mt-1 text-2xl font-semibold text-foreground">Email Analysis Report</h3></div>
              <div className="text-sm text-foreground0"><p>Scan ID</p><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{report.scan_id}</p></div>
            </div>

            <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-surface-muted sm:grid-cols-3">
              <div className="bg-surface p-5"><p className="text-xs uppercase tracking-wide text-foreground0">Final verdict</p><ClassificationBadge classification={report.final_classification} className="mt-3" /></div>
              <div className="bg-surface p-5"><p className="text-xs uppercase tracking-wide text-foreground0">Risk score</p><p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{report.risk_score}<span className="text-sm font-normal text-foreground0">/100</span></p><Progress value={report.risk_score} className={cn('mt-3 h-2 bg-surface-muted', report.risk_score >= 70 ? '[&>div]:bg-danger' : report.risk_score >= 30 ? '[&>div]:bg-warning' : '[&>div]:bg-success')} /></div>
              <div className="bg-surface p-5"><p className="text-xs uppercase tracking-wide text-foreground0">Confidence</p><p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">{Math.round(report.confidence * 100)}%</p><p className="mt-1 text-xs text-foreground0">Decision certainty</p></div>
            </div>

            <nav aria-label="Report sections" className="flex gap-2 overflow-x-auto border-b border-border pb-4 text-xs"><a href="#report-indicators" className="whitespace-nowrap rounded-md bg-surface px-3 py-2 text-muted-foreground hover:text-foreground">Indicators</a><a href="#report-urls" className="whitespace-nowrap rounded-md bg-surface px-3 py-2 text-muted-foreground hover:text-foreground">URLs</a><a href="#report-attachments" className="whitespace-nowrap rounded-md bg-surface px-3 py-2 text-muted-foreground hover:text-foreground">Attachments</a><a href="#report-recommendations" className="whitespace-nowrap rounded-md bg-surface px-3 py-2 text-muted-foreground hover:text-foreground">Recommendations</a><a href="#report-engines" className="whitespace-nowrap rounded-md bg-surface px-3 py-2 text-muted-foreground hover:text-foreground">Engine metadata</a></nav>

            <div className="grid gap-6 lg:grid-cols-2">
              <Card className="border-border bg-surface/80">
                <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><Mail className="h-4 w-4 text-foreground0" aria-hidden="true" />Report metadata</CardTitle></CardHeader>
                <CardContent><dl className="space-y-3 text-sm">{[
                  ['Report timestamp', formatReportDate(report.report_generated_at)],
                  ['Scan timestamp', formatReportDate(report.scan_timestamp)],
                  ['Subject', report.subject],
                  ['Sender', report.sender],
                  ['Recipients', report.recipients.join(', ') || 'Not recorded'],
                  ['Input mode', formatReportInputMode(report.input_mode)],
                ].map(([label, value]) => <div key={label} className="grid grid-cols-[120px_1fr] gap-3"><dt className="text-foreground0">{label}</dt><dd className="break-all text-muted-foreground">{value}</dd></div>)}</dl></CardContent>
              </Card>
              <Card id="report-engines" className="scroll-mt-6 border-border bg-surface/80">
                <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><FileText className="h-4 w-4 text-foreground0" aria-hidden="true" />Detection engines</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div><div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-foreground">Rule engine</p><Badge variant="outline" className="border-success/30 bg-success/10 capitalize text-success">{report.rule_engine.status}</Badge></div><p className="mt-1 text-xs text-foreground0">Version: {report.rule_engine.version || 'Not recorded'}</p></div>
                  <Separator className="bg-surface-muted" />
                  <div><div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-foreground">ML engine</p><Badge variant="outline" className="border-input bg-background capitalize text-muted-foreground">{report.ml_engine.status}</Badge></div><p className="mt-1 text-xs text-foreground0">Version: {report.ml_engine.version || 'Not recorded'}</p></div>
                </CardContent>
              </Card>
            </div>

            <Card id="report-indicators" className="scroll-mt-6 border-border bg-surface/80">
              <CardHeader><CardTitle className="text-base text-foreground">Detected indicators</CardTitle></CardHeader>
              <CardContent>{report.detected_indicators.length ? <div className="space-y-4">{report.detected_indicators.map((indicator, index) => <div key={`${indicator.code}-${index}`}>{index > 0 && <Separator className="mb-4 bg-surface-muted" />}<div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-foreground">{indicator.title}</p>{indicator.description && <p className="mt-1 text-sm leading-5 text-muted-foreground">{indicator.description}</p>}</div><Badge variant="outline" className={cn('shrink-0 capitalize', severityStyles[indicator.severity])}>{indicator.severity} · +{indicator.score}</Badge></div><div className="mt-2 rounded-md border border-border bg-background/60 px-3 py-2 text-xs"><span className="text-foreground0">Evidence: </span><span className="break-words text-muted-foreground">{indicator.evidence || 'Pattern-based detection'}</span></div></div>)}</div> : <p className="text-sm text-foreground0">No indicators detected.</p>}</CardContent>
            </Card>

            <div className="grid gap-6 lg:grid-cols-2">
              <Card id="report-recommendations" className="scroll-mt-6 border-border bg-surface/80"><CardHeader><CardTitle className="text-base text-foreground">Recommendations</CardTitle></CardHeader><CardContent>{report.recommendations.length ? <ol className="space-y-3">{report.recommendations.map((item, index) => <li key={`${item}-${index}`} className="flex gap-3 text-sm leading-6 text-muted-foreground"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-muted text-[10px] text-muted-foreground">{index + 1}</span>{item}</li>)}</ol> : <p className="text-sm text-foreground0">No recommendations recorded.</p>}</CardContent></Card>
              <Card id="report-urls" className="scroll-mt-6 border-border bg-surface/80"><CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><LinkIcon className="h-4 w-4 text-foreground0" aria-hidden="true" />Extracted URLs</CardTitle></CardHeader><CardContent>{report.extracted_urls.length ? <ul className="space-y-2">{report.extracted_urls.map((url, index) => <li key={`${url}-${index}`} className="break-all rounded-md border border-border bg-background/60 p-3 font-mono text-xs text-muted-foreground">{url}</li>)}</ul> : <p className="text-sm text-foreground0">No URLs recorded.</p>}</CardContent></Card>
            </div>

            <Card id="report-attachments" className="scroll-mt-6 border-border bg-surface/80">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base text-foreground"><Paperclip className="h-4 w-4 text-foreground0" aria-hidden="true" />Attachment metadata</CardTitle></CardHeader>
              <CardContent className={report.attachments.length ? 'px-0' : undefined}>{report.attachments.length ? <Table><TableHeader><TableRow className="border-border"><TableHead className="text-foreground0">Filename</TableHead><TableHead className="text-foreground0">Content type</TableHead><TableHead className="text-foreground0">Disposition</TableHead><TableHead className="text-right text-foreground0">Size</TableHead></TableRow></TableHeader><TableBody>{report.attachments.map((attachment, index) => <TableRow key={`${attachment.filename}-${index}`} className="border-border"><TableCell className="text-muted-foreground">{attachment.filename || 'Unnamed'}</TableCell><TableCell className="text-muted-foreground">{attachment.content_type || 'Unknown'}</TableCell><TableCell className="text-muted-foreground">{attachment.disposition || 'Not recorded'}</TableCell><TableCell className="text-right tabular-nums text-muted-foreground">{formatFileSize(attachment.size_bytes)}</TableCell></TableRow>)}</TableBody></Table> : <p className="text-sm text-foreground0">No attachment metadata recorded.</p>}</CardContent>
            </Card>

            <div className="flex gap-3 rounded-lg border border-primary/20 bg-primary/5 p-4 text-sm leading-6 text-primary"><Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><div><p className="font-medium">Privacy notice</p><p className="mt-1 text-primary/80">{report.privacy_disclaimer}</p></div></div>
          </div>
        </div>
      </section>
    </div>
  );
}
