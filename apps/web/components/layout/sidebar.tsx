"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  MailSearch, 
  History, 
  FileText, 
  Settings, 
  ShieldAlert 
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, active: true },
  { name: 'Analyze Email', href: '/analyze', icon: MailSearch, active: true },
  { name: 'Scan History', href: '/history', icon: History, active: false },
  { name: 'Reports', href: '/reports', icon: FileText, active: false },
  { name: 'Settings', href: '/settings', icon: Settings, active: false },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 -translate-x-full border-r border-slate-800 bg-slate-950 transition-transform lg:translate-x-0">
      <div className="flex h-full flex-col px-3 py-4">
        <div className="mb-10 flex items-center gap-2 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white">
            <ShieldAlert size={20} aria-hidden="true" />
          </div>
          <span className="text-lg font-bold tracking-tight text-slate-100">
            PhishPhage AI
          </span>
        </div>

        <nav className="flex-1 space-y-1">
          {navigation.map((item) => {
            const isActive = pathname === item.href;
            return (
              item.active ? <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive 
                    ? "bg-slate-900 text-blue-400 shadow-sm ring-1 ring-slate-800"
                    : "text-slate-400 hover:bg-slate-900 hover:text-slate-100",
                )}
              >
                <item.icon size={18} aria-hidden="true" />
                {item.name}
              </Link> : <TooltipProvider key={item.name}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span aria-disabled="true" className="flex cursor-not-allowed items-center justify-between rounded-md px-3 py-2 text-sm font-medium text-slate-600">
                      <span className="flex items-center gap-3"><item.icon size={18} aria-hidden="true" />{item.name}</span>
                      <span className="text-[9px] uppercase tracking-wide text-slate-700">Soon</span>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="border-slate-700 bg-slate-900 text-slate-200">Coming soon</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            );
          })}
        </nav>

        <div className="mt-auto border-t border-slate-800 px-2 pt-4">
          <div className="flex items-center gap-3 rounded-lg bg-slate-900 px-2 py-3 text-xs font-medium text-slate-400">
            <div className="h-2 w-2 rounded-full bg-emerald-400" aria-hidden="true" />
            Demo status: Operational
          </div>
        </div>
      </div>
    </aside>
  );
}
