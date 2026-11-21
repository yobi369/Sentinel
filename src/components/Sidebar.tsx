import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Crosshair,
  Grid,
  FileSearch,
  Network,
  ClipboardCheck,
  TerminalSquare,
  Lock,
  Shield,
} from 'lucide-react';
import { UserRole } from '../types';

export type TabType =
  | 'dashboard'
  | 'defender'
  | 'pentest'
  | 'sandbox'
  | 'topology'
  | 'mitre'
  | 'compliance'
  | 'copilot';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  activeAlertsCount: number;
  role: UserRole;
  setRole: (role: UserRole) => void;
  onOpenAuditLogs: () => void;
  auditEntriesCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  activeAlertsCount,
  role,
  setRole,
  onOpenAuditLogs,
  auditEntriesCount,
}) => {
  const sections: {
    heading: string;
    items: { id: TabType; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }[];
  }[] = [
    {
      heading: 'Operations',
      items: [
        { id: 'dashboard', label: 'Incident Queue', icon: LayoutDashboard, count: activeAlertsCount },
        { id: 'defender', label: 'Detection & SOAR', icon: ShieldAlert },
      ],
    },
    {
      heading: 'Exposure & Analysis',
      items: [
        { id: 'pentest', label: 'Attack Surface', icon: Crosshair },
        { id: 'sandbox', label: 'Artifact Analyzer', icon: FileSearch },
        { id: 'topology', label: 'Asset Inventory', icon: Network },
      ],
    },
    {
      heading: 'Governance',
      items: [
        { id: 'mitre', label: 'ATT&CK & Intel', icon: Grid },
        { id: 'compliance', label: 'Compliance Audit', icon: ClipboardCheck },
        { id: 'copilot', label: 'Security Copilot', icon: TerminalSquare },
      ],
    },
  ];

  return (
    <aside className="w-full md:w-60 bg-[#0E1117] border-b md:border-b-0 md:border-r border-white/[0.08] flex flex-col justify-between shrink-0">
      <div>
        {/* Brand Zone: Single clean lockup */}
        <div className="h-14 px-5 border-b border-white/[0.08] flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-display font-bold text-base tracking-tight text-white whitespace-nowrap">
            SentinelAI
          </span>
        </div>

        {/* Navigation Groups */}
        <nav className="p-3 space-y-5">
          {sections.map((section) => (
            <div key={section.heading} className="space-y-1">
              <div className="px-2.5 pb-1 text-[11px] font-medium text-zinc-500">
                {section.heading}
              </div>
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center justify-between px-2.5 py-2 rounded-md text-[13px] font-medium transition-colors cursor-pointer whitespace-nowrap ${
                      isActive
                        ? 'bg-white/[0.07] text-white'
                        : 'text-zinc-400 hover:text-zinc-100 hover:bg-white/[0.03]'
                    }`}
                  >
                    <span className="flex items-center gap-2.5 min-w-0">
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-zinc-500'}`} />
                      <span className="truncate">{item.label}</span>
                    </span>
                    {typeof item.count === 'number' && item.count > 0 && (
                      <span className="text-xs font-mono tabular-nums text-zinc-400">
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* Bottom Operator Context & Audit Ledger Trigger */}
      <div className="p-3 border-t border-white/[0.08] space-y-2.5">
        <div>
          <label className="block text-[11px] text-zinc-500 px-1 mb-1">Active Role</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs text-zinc-200 focus:outline-none focus:border-blue-500/60 cursor-pointer"
          >
            <option value="SOC Tier 1 Analyst">SOC Tier 1 Analyst</option>
            <option value="SOC Tier 3 Lead">SOC Tier 3 Lead</option>
            <option value="Red Team Assessor">Red Team Assessor</option>
            <option value="Compliance Lead">Compliance Lead</option>
            <option value="CISO">CISO</option>
          </select>
        </div>

        <button
          onClick={onOpenAuditLogs}
          className="w-full flex items-center justify-between px-2.5 py-2 rounded-md text-xs font-medium text-zinc-300 hover:text-white bg-[#090B0F] hover:bg-white/[0.04] border border-white/[0.08] transition-colors cursor-pointer"
        >
          <span className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-zinc-400" />
            <span>Audit Ledger</span>
          </span>
          <span className="font-mono text-[11px] tabular-nums text-zinc-500">{auditEntriesCount}</span>
        </button>
      </div>
    </aside>
  );
};
