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
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
      <div role="alertdialog" aria-modal="true" aria-labelledby="confirmation-title" aria-describedby="confirmation-description" className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-2xl shadow-black/40">
        <div className="flex items-start gap-4">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-rose-500/30 bg-rose-500/10 text-rose-300">
            <AlertTriangle size={19} aria-hidden="true" />
          </span>
          <div>
            <h2 id="confirmation-title" className="text-base font-semibold text-slate-100">{title}</h2>
            <p id="confirmation-description" className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button type="button" variant="outline" onClick={onCancel} className="border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white">Cancel</Button>
          <Button type="button" autoFocus onClick={onConfirm} className={tone === 'danger' ? 'bg-rose-600 text-white hover:bg-rose-500' : 'bg-blue-600 text-white hover:bg-blue-500'}>{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}
