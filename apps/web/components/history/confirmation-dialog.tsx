'use client';

import { useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';

import { Button } from '@/components/ui/button';

interface ConfirmationDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  tone?: 'danger' | 'primary';
  onCancel: () => void;
  onConfirm: () => void;
}

export function ConfirmationDialog({ open, title, description, confirmLabel, tone = 'danger', onCancel, onConfirm }: ConfirmationDialogProps) {
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onCancel, open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
      <div role="alertdialog" aria-modal="true" aria-labelledby="confirmation-title" aria-describedby="confirmation-description" className="w-full max-w-md rounded-lg border border-input bg-surface p-6 shadow-2xl shadow-black/40">
        <div className="flex items-start gap-4">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-danger/30 bg-danger/10 text-danger">
            <AlertTriangle size={19} aria-hidden="true" />
          </span>
          <div>
            <h2 id="confirmation-title" className="text-base font-semibold text-foreground">{title}</h2>
            <p id="confirmation-description" className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button type="button" variant="outline" onClick={onCancel} className="border-input bg-surface text-muted-foreground hover:bg-surface-muted hover:text-foreground">Cancel</Button>
          <Button type="button" autoFocus onClick={onConfirm} className={tone === 'danger' ? 'bg-danger text-primary-foreground hover:bg-danger' : 'bg-primary text-primary-foreground hover:bg-primary'}>{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}
