import { MonitorCog, ShieldCheck } from 'lucide-react';

export function TopNav() {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/95 px-4 backdrop-blur lg:px-6">
      <div className="flex items-center gap-3">
        <span className="flex h-8 w-8 items-center justify-center rounded-md bg-slate-900 text-blue-400"><MonitorCog size={17} aria-hidden="true" /></span>
        <div><p className="text-xs font-semibold text-slate-200">Local Workspace</p><p className="mt-0.5 text-[10px] text-slate-500">Analysis Console</p></div>
      </div>
      <div className="flex items-center gap-2 text-xs text-slate-500"><ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" /><span className="hidden sm:inline">No account required</span></div>
    </header>
  );
}
