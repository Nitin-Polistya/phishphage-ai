"use client";

import { Bell, Search, User } from 'lucide-react';

export function TopNav() {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/95 px-4 backdrop-blur lg:px-6">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-full max-w-md hidden md:block">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input 
            type="text" 
            placeholder="Search scans and threats..."
            aria-label="Search scans and threats"
            className="w-full rounded-md border border-slate-800 bg-slate-900 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button type="button" aria-label="Notifications" className="relative rounded-full p-2 text-slate-400 transition-colors hover:bg-slate-900 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <Bell size={20} aria-hidden="true" />
          <span className="absolute right-2 top-2 h-2 w-2 rounded-full border-2 border-slate-950 bg-rose-500" aria-hidden="true" />
        </button>
        <div className="mx-1 h-8 w-px bg-slate-800" />
        <div className="flex items-center gap-3 pl-1">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-800 text-slate-300">
            <User size={18} aria-hidden="true" />
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-semibold leading-none text-slate-200">Admin User</p>
            <p className="text-[10px] text-slate-500 leading-tight mt-1">Security Analyst</p>
          </div>
        </div>
      </div>
    </header>
  );
}
