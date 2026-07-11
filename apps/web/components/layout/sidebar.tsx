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
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 border-r bg-slate-50/50 transition-transform -translate-x-full lg:translate-x-0">
      <div className="flex h-full flex-col px-3 py-4">
        <div className="mb-10 flex items-center gap-2 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white">
            <ShieldAlert size={20} />
          </div>
          <span className="text-lg font-bold tracking-tight text-slate-900">
            PhishShield AI
          </span>
        </div>

        <nav className="flex-1 space-y-1">
          {navigation.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive 
                    ? "bg-white text-blue-600 shadow-sm ring-1 ring-slate-200" 
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
                  !item.active && "opacity-50 cursor-not-allowed pointer-events-none"
                )}
              >
                <item.icon size={18} />
                {item.name}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto border-t pt-4 px-2">
          <div className="flex items-center gap-3 px-2 py-3 rounded-lg bg-slate-100/50 text-slate-600 text-xs font-medium">
            <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
            Backend Connected
          </div>
        </div>
      </div>
    </aside>
  );
}