'use client';

import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import { Download, Eye, MoreVertical, Printer } from 'lucide-react';

import { Button } from '@/components/ui/button';
import type { ScanRecord } from '@/types';

interface ReportActionsMenuProps {
  scan: ScanRecord;
  onView: (scan: ScanRecord) => void;
  onJson: (scan: ScanRecord) => void;
  onCsv: (scan: ScanRecord) => void;
  onPrint: (scan: ScanRecord) => void;
}

const MENU_WIDTH = 176;
const MENU_HEIGHT = 172;
const VIEWPORT_GUTTER = 8;

export function ReportActionsMenu({ scan, onView, onJson, onCsv, onPrint }: ReportActionsMenuProps) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = `report-actions-${useId().replaceAll(':', '')}`;

  const actions = [
    { label: 'View', icon: Eye, run: () => onView(scan) },
    { label: 'Export JSON', icon: Download, run: () => onJson(scan) },
    { label: 'Export CSV', icon: Download, run: () => onCsv(scan) },
    { label: 'Print', icon: Printer, run: () => onPrint(scan) },
  ];

  const openMenu = () => {
    const bounds = buttonRef.current?.getBoundingClientRect();
    if (!bounds) return;
    const left = Math.min(window.innerWidth - MENU_WIDTH - VIEWPORT_GUTTER, Math.max(VIEWPORT_GUTTER, bounds.right - MENU_WIDTH));
    const below = bounds.bottom + 4;
    const top = below + MENU_HEIGHT <= window.innerHeight - VIEWPORT_GUTTER
      ? below
      : Math.max(VIEWPORT_GUTTER, bounds.top - MENU_HEIGHT - 4);
    setPosition({ top, left });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const focusFrame = window.requestAnimationFrame(() => menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus());
    const close = () => setOpen(false);
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!menuRef.current?.contains(target) && !buttonRef.current?.contains(target)) close();
    };
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') {
        close();
        buttonRef.current?.focus();
      }
    };
    document.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [open]);

  const handleMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const items = [...(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])];
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    const direction = event.key === 'ArrowDown' ? 1 : -1;
    items[(current + direction + items.length) % items.length]?.focus();
  };

  return (
    <>
      <Button
        ref={buttonRef}
        type="button"
        variant="ghost"
        size="icon"
        aria-label={`Report actions for ${scan.subject}`}
        aria-haspopup="menu"
        aria-controls={open ? menuId : undefined}
        aria-expanded={open}
        onClick={() => open ? setOpen(false) : openMenu()}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (!open) openMenu();
          }
        }}
        className="theme-link h-8 w-8 hover:bg-surface-muted"
      >
        <MoreVertical aria-hidden="true" />
      </Button>
      {open && createPortal(
        <div ref={menuRef} id={menuId} role="menu" aria-label={`Actions for ${scan.subject}`} onKeyDown={handleMenuKeyDown} style={{ top: position.top, left: position.left }} className="fixed z-[80] w-44 rounded-md border border-input bg-background p-1 shadow-xl shadow-black/30">
          {actions.map((action) => (
            <button key={action.label} type="button" role="menuitem" onClick={() => { setOpen(false); action.run(); }} className="theme-link flex w-full items-center gap-2 rounded-sm px-3 py-2 text-left text-sm hover:bg-surface-muted focus-visible:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <action.icon className="h-4 w-4" aria-hidden="true" />{action.label}
            </button>
          ))}
        </div>,
        document.body,
      )}
    </>
  );
}
