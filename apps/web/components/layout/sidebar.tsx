'use client';

import { useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronLeft, ChevronRight, FileText, History, LayoutDashboard, MailSearch, Settings, ShieldAlert, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Analyze Email', href: '/analyze', icon: MailSearch },
  { name: 'Scan History', href: '/history', icon: History },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Settings', href: '/settings', icon: Settings },
];

interface SidebarProps {
  collapsed: boolean;
  mobileOpen: boolean;
  isDesktop: boolean;
  onToggleCollapsed: () => void;
  onCloseMobile: () => void;
}

export function Sidebar({ collapsed, mobileOpen, isDesktop, onToggleCollapsed, onCloseMobile }: SidebarProps) {
  const pathname = usePathname();
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const handleNavigate = () => {
    if (!isDesktop) onCloseMobile();
  };

  useEffect(() => {
    if (!mobileOpen) return;
    closeButtonRef.current?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseMobile();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [mobileOpen, onCloseMobile]);

  return (
    <TooltipProvider delayDuration={250}>
      {mobileOpen && <button type="button" aria-label="Close navigation overlay" onClick={onCloseMobile} className="fixed inset-0 z-40 bg-background/75 backdrop-blur-sm lg:hidden" />}
      <aside
        id="application-sidebar"
        aria-label="Application navigation"
        aria-hidden={!isDesktop && !mobileOpen ? true : undefined}
        inert={!isDesktop && !mobileOpen ? true : undefined}
        className={cn(
          'fixed left-0 top-0 z-50 h-screen w-64 border-r border-border bg-background transition-[width,transform] duration-200',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
          collapsed ? 'lg:w-20' : 'lg:w-64',
        )}
      >
        <div className="relative flex h-full flex-col px-3 py-4">
          <Link href="/" aria-label="PhishShield AI home" onClick={handleNavigate} className={cn('mb-10 flex items-center gap-2 rounded-md px-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', collapsed && 'lg:justify-center lg:px-0')}>
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldAlert size={20} aria-hidden="true" /></span>
            <span className={cn('whitespace-nowrap text-lg font-bold tracking-tight text-foreground', collapsed && 'lg:sr-only')}>PhishShield AI</span>
          </Link>

          <Button ref={closeButtonRef} type="button" variant="ghost" size="icon" aria-label="Close navigation" onClick={onCloseMobile} className="theme-link absolute right-3 top-4 hover:bg-surface lg:hidden"><X aria-hidden="true" /></Button>
          <Button type="button" variant="outline" size="icon" aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'} aria-controls="application-sidebar" aria-expanded={!collapsed} onClick={onToggleCollapsed} className="theme-link absolute -right-3 top-16 hidden h-7 w-7 rounded-full border-input bg-background shadow hover:bg-surface-muted lg:flex">
            {collapsed ? <ChevronRight aria-hidden="true" /> : <ChevronLeft aria-hidden="true" />}
          </Button>

          <nav className="flex-1 space-y-1">
            {navigation.map((item) => {
              const isActive = pathname === item.href;
              const link = (
                <Link
                  href={item.href}
                  onClick={handleNavigate}
                  aria-current={isActive ? 'page' : undefined}
                  aria-label={collapsed ? item.name : undefined}
                  className={cn(
                    'flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-[color,background-color,transform] duration-150 active:scale-[0.98] motion-reduce:transition-none motion-reduce:active:scale-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                    collapsed && 'lg:justify-center lg:px-2',
                    isActive ? 'theme-active-link bg-surface shadow-sm ring-1 ring-border' : 'theme-link hover:bg-surface',
                  )}
                >
                  <item.icon size={18} className="shrink-0" aria-hidden="true" />
                  <span className={cn('whitespace-nowrap', collapsed && 'lg:sr-only')}>{item.name}</span>
                </Link>
              );

              return collapsed ? (
                <Tooltip key={item.name}>
                  <TooltipTrigger asChild>{link}</TooltipTrigger>
                  <TooltipContent side="right" className="hidden border-input bg-surface text-foreground lg:block">{item.name}</TooltipContent>
                </Tooltip>
              ) : <div key={item.name}>{link}</div>;
            })}
          </nav>

          <div className={cn('mt-auto border-t border-border px-2 pt-4', collapsed && 'lg:hidden')}>
            <div className="rounded-lg bg-surface px-3 py-3"><p className="text-xs font-semibold text-muted-foreground">Local Workspace</p><p className="mt-1 text-[10px] leading-4 text-foreground0">Browser-only data</p></div>
          </div>
        </div>
      </aside>
    </TooltipProvider>
  );
}
