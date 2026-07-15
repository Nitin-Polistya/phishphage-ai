'use client';

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';

import { readSidebarCollapsed, writeSidebarCollapsed } from '@/lib/sidebar-state';
import { cn } from '@/lib/utils';
import { Sidebar } from './sidebar';
import { TopNav } from './top-nav';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isDesktop, setIsDesktop] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setCollapsed(readSidebarCollapsed());
    const media = window.matchMedia('(min-width: 1024px)');
    const syncViewport = () => {
      setIsDesktop(media.matches);
      if (media.matches) setMobileOpen(false);
    };
    syncViewport();
    media.addEventListener('change', syncViewport);
    return () => media.removeEventListener('change', syncViewport);
  }, []);

  const toggleCollapsed = useCallback(() => {
    setCollapsed((current) => {
      const next = !current;
      writeSidebarCollapsed(next);
      return next;
    });
  }, []);

  const closeMobile = useCallback(() => {
    setMobileOpen(false);
    window.requestAnimationFrame(() => menuButtonRef.current?.focus());
  }, []);

  return (
    <div className="flex min-h-screen bg-slate-950">
      <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} isDesktop={isDesktop} onToggleCollapsed={toggleCollapsed} onCloseMobile={closeMobile} />
      <div inert={mobileOpen ? true : undefined} className={cn('flex min-w-0 flex-1 flex-col transition-[padding] duration-200', collapsed ? 'lg:pl-20' : 'lg:pl-64')}>
        <TopNav mobileOpen={mobileOpen} menuButtonRef={menuButtonRef} onOpenSidebar={() => setMobileOpen(true)} />
        <main className="min-w-0 p-4 sm:p-6 lg:p-8">
          <div className="mx-auto max-w-7xl">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
