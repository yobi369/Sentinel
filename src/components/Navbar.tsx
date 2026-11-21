import React, { useState } from 'react';
import { Search, Terminal, ShieldCheck, AlertCircle } from 'lucide-react';
import { UserRole } from '../types';

interface NavbarProps {
  activeTabLabel: string;
  role: UserRole;
  auditValid: boolean;
  onQuickSearch: (query: string) => void;
  onOpenCopilot: () => void;
  onOpenAuditLogs: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTabLabel,
  role,
  auditValid,
  onQuickSearch,
  onOpenCopilot,
  onOpenAuditLogs,
}) => {
  const [searchValue, setSearchValue] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchValue.trim()) return;
    onQuickSearch(searchValue.trim());
  };

  return (
    <header className="h-14 bg-[#0E1117] border-b border-white/[0.08] px-6 sticky top-0 z-30 flex items-center justify-between gap-8">
      {/* Zone 1: Contextual Breadcrumb */}
      <div className="flex items-center gap-2 text-sm min-w-0">
        <span className="text-zinc-500 font-medium whitespace-nowrap">SentinelAI</span>
        <span className="text-zinc-600" aria-hidden="true">/</span>
        <span className="text-zinc-100 font-medium truncate">{activeTabLabel}</span>
      </div>

      {/* Zone 2: Global IOC / Telemetry Lookup */}
      <form onSubmit={handleSubmit} className="hidden md:flex items-center flex-1 max-w-md">
        <div className="relative w-full">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="Lookup IP, domain, SHA-256 hash, or CVE..."
            className="w-full h-8 bg-[#090B0F] border border-white/[0.08] focus:border-blue-500/70 rounded-md pl-8 pr-3 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none transition-colors"
          />
        </div>
      </form>

      {/* Zone 3: Operator Context + Primary Action */}
      <div className="flex items-center gap-4 shrink-0">
        <button
          onClick={onOpenAuditLogs}
          className="hidden sm:flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          title="Inspect SHA-256 hash-chained audit ledger"
        >
          {auditValid ? (
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
          ) : (
            <AlertCircle className="w-3.5 h-3.5 text-rose-500" />
          )}
          <span className="font-mono">{role}</span>
        </button>

        <button
          onClick={onOpenCopilot}
          className="h-8 px-3.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Ask Copilot</span>
        </button>
      </div>
    </header>
  );
};
