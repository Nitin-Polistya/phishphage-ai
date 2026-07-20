import type { RefObject } from 'react';
import { Menu, MonitorCog, ShieldCheck } from 'lucide-react';

import { Button } from '@/components/ui/button';

interface TopNavProps {
  mobileOpen: boolean;
  menuButtonRef: RefObject<HTMLButtonElement | null>;
  onOpenSidebar: () => void;
}

export function TopNav({ mobileOpen, menuButtonRef, onOpenSidebar }: TopNavProps) {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur lg:px-6">
      <div className="flex items-center gap-3">
        <Button ref={menuButtonRef} type="button" variant="ghost" size="icon" aria-label="Open navigation" aria-controls="application-sidebar" aria-expanded={mobileOpen} onClick={onOpenSidebar} className="theme-link hover:bg-surface lg:hidden"><Menu aria-hidden="true" /></Button>
        <span className="flex h-8 w-8 items-center justify-center rounded-md bg-surface text-primary"><MonitorCog size={17} aria-hidden="true" /></span>
        <div><p className="text-xs font-semibold text-foreground">Local Workspace</p><p className="mt-0.5 text-[10px] text-foreground0">Analysis Console</p></div>
      </div>
      <div className="flex items-center gap-2 text-xs text-foreground0"><ShieldCheck className="h-4 w-4 text-success" aria-hidden="true" /><span className="hidden sm:inline">No account required</span></div>
    </header>
  );
}
