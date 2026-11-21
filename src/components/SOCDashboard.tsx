import React, { useState } from 'react';
import {
  Search,
  Play,
  Eye,
  Plus,
  ArrowUpRight,
  CheckCircle2,
  X,
} from 'lucide-react';
import { IncidentAlert, Playbook, Asset } from '../types';
import { TabType } from './Sidebar';

interface SOCDashboardProps {
  alerts: IncidentAlert[];
  playbooks: Playbook[];
  assets: Asset[];
  auditValid: boolean;
  auditCount: number;
  onSelectAlert: (alert: IncidentAlert) => void;
  onExecutePlaybook: (playbookId: string, alertId?: string) => void;
  onIngestLog: (source: string, host: string, raw: string) => Promise<void>;
  onNavigateTab: (tab: TabType) => void;
}

export const SOCDashboard: React.FC<SOCDashboardProps> = ({
  alerts,
  playbooks,
  assets,
  auditValid,
  auditCount,
  onSelectAlert,
  onExecutePlaybook,
  onIngestLog,
  onNavigateTab,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Live Log Ingestion Drawer
  const [ingestOpen, setIngestOpen] = useState(false);
  const [ingestSource, setIngestSource] = useState('edr');
  const [ingestHost, setIngestHost] = useState('prod-api-02');
  const [ingestRaw, setIngestRaw] = useState(
    '2026-11-20T23:10:12.004Z sysmon[2201]: EventID=4688 Host=prod-api-02 User=svc_deploy CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"'
  );
  const [ingesting, setIngesting] = useState(false);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSev = filterSeverity === 'ALL' || alert.severity.toUpperCase() === filterSeverity;
    const matchesStatus = filterStatus === 'ALL' || alert.status.toUpperCase() === filterStatus;
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      alert.title.toLowerCase().includes(q) ||
      alert.assetName.toLowerCase().includes(q) ||
      alert.sourceIp.includes(q) ||
      alert.id.toLowerCase().includes(q) ||
      alert.mitreTechniqueId.toLowerCase().includes(q);
    return matchesSev && matchesStatus && matchesSearch;
  });

  const activeCount = alerts.filter((a) => a.status === 'Active' || a.status === 'Investigating').length;
  const criticalCount = alerts.filter((a) => a.severity === 'Critical' && a.status === 'Active').length;
  const protectedAssetsCount = assets.filter((a) => a.status === 'Protected' || a.status === 'Isolated').length;
  const autoPlaybooksCount = playbooks.filter((p) => p.autoTriggerEnabled).length;

  const getSeverityMarker = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return { dot: 'bg-rose-500', text: 'text-rose-400' };
      case 'High':
        return { dot: 'bg-amber-500', text: 'text-amber-400' };
      case 'Medium':
        return { dot: 'bg-sky-400', text: 'text-sky-400' };
      default:
        return { dot: 'bg-zinc-500', text: 'text-zinc-400' };
    }
  };

  const handleSubmitIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ingestRaw.trim() || ingesting) return;
    setIngesting(true);
    try {
      await onIngestLog(ingestSource, ingestHost, ingestRaw);
      setIngestOpen(false);
    } finally {
      setIngesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">Security Operations Overview</h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Real-time incident queue, automated containment playbooks, and fleet posture telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={() => setIngestOpen((v) => !v)}
            className="h-8 px-3 bg-[#12161E] hover:bg-white/[0.06] text-zinc-200 border border-white/[0.08] rounded-md text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5 text-zinc-400" />
            <span>Ingest Telemetry Event</span>
          </button>
          <button
            onClick={() => onNavigateTab('pentest')}
            className="h-8 px-3.5 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-xs font-medium transition-colors cursor-pointer whitespace-nowrap"
          >
            Inspect Attack Surface
          </button>
        </div>
      </div>

      {/* Optional Live Log Ingestion Panel */}
      {ingestOpen && (
        <form
          onSubmit={handleSubmitIngest}
          className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-200">
              Submit Raw Log Event to Detection Pipeline
            </span>
            <button
              type="button"
              onClick={() => setIngestOpen(false)}
              className="text-zinc-500 hover:text-zinc-200 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] text-zinc-500 mb-1">Telemetry Source</label>
              <select
                value={ingestSource}
                onChange={(e) => setIngestSource(e.target.value)}
                className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs font-mono text-zinc-200 focus:outline-none"
              >
                <option value="edr">edr (Sysmon / Osquery)</option>
                <option value="suricata">suricata (IDS/IPS)</option>
                <option value="zeek">zeek (Network Flow)</option>
                <option value="syslog">syslog (OS / Audit)</option>
              </select>
            </div>
            <div>
              <label className="block text-[11px] text-zinc-500 mb-1">Source Host</label>
              <input
                type="text"
                value={ingestHost}
                onChange={(e) => setIngestHost(e.target.value)}
                className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs font-mono text-zinc-200 focus:outline-none"
              />
            </div>
            <div className="flex items-end gap-2">
              <button
                type="button"
                onClick={() =>
                  setIngestRaw(
                    '2026-11-20T23:14:00Z suricata[991]: [1:2024109:3] ET MALWARE Cobalt Strike Beacon {TCP} 10.0.1.45:51092 -> 185.220.101.5:443'
                  )
                }
                className="h-8 px-2.5 bg-[#090B0F] border border-white/[0.08] hover:border-white/20 text-[11px] font-mono text-zinc-400 rounded-md cursor-pointer whitespace-nowrap"
              >
                Load C2 Sample
              </button>
              <button
                type="submit"
                disabled={ingesting}
                className="h-8 px-4 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md cursor-pointer disabled:opacity-50 whitespace-nowrap"
              >
                {ingesting ? 'Evaluating...' : 'Evaluate & Ingest'}
              </button>
            </div>
          </div>
          <textarea
            rows={2}
            value={ingestRaw}
            onChange={(e) => setIngestRaw(e.target.value)}
            className="w-full bg-[#090B0F] border border-white/[0.08] rounded-md p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-blue-500/60"
          />
        </form>
      )}

      {/* Flat Single-Elevation KPI Strip */}
      <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.08]">
        <div className="p-4">
          <div className="text-xs text-zinc-400">Open Incidents</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-white">
              {activeCount}
            </span>
            <span className="text-xs font-mono text-rose-400">
              {criticalCount} critical
            </span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs text-zinc-400">Monitored Workloads</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-white">
              {assets.length}
            </span>
            <span className="text-xs font-mono text-zinc-400">
              {protectedAssetsCount} healthy/isolated
            </span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs text-zinc-400">SOAR Auto-Remediation</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-semibold font-mono tabular-nums text-white">
              {autoPlaybooksCount}/{playbooks.length}
            </span>
            <span className="text-xs font-mono text-zinc-400">policies armed</span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs text-zinc-400">Audit Hash Chain</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className={`text-2xl font-semibold font-mono tabular-nums ${auditValid ? 'text-emerald-400' : 'text-rose-400'}`}>
              {auditValid ? 'Verified' : 'Tampered'}
            </span>
            <span className="text-xs font-mono text-zinc-400">
              {auditCount} SHA-256 blocks
            </span>
          </div>
        </div>
      </div>

      {/* Main Split Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Incident Queue Table (2 cols) */}
        <div className="xl:col-span-2 bg-[#0E1117] border border-white/[0.08] rounded-lg flex flex-col">
          <div className="px-4 py-3 border-b border-white/[0.08] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold text-white">Incident Triage Queue</h2>
              <span className="text-xs font-mono text-zinc-500 tabular-nums">
                {filteredAlerts.length} shown
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter ID, host, IP, MITRE..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="h-8 bg-[#090B0F] border border-white/[0.08] rounded-md pl-8 pr-3 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-blue-500/60 w-44 sm:w-52"
                />
              </div>

              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs text-zinc-300 focus:outline-none cursor-pointer"
              >
                <option value="ALL">All severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
              </select>

              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs text-zinc-300 focus:outline-none cursor-pointer"
              >
                <option value="ALL">All statuses</option>
                <option value="ACTIVE">Active</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="MITIGATED">Mitigated</option>
                <option value="CLOSED">Closed</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500">
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-3">ID</th>
                  <th className="py-2.5 px-3">Detection</th>
                  <th className="py-2.5 px-3">Host / Source IP</th>
                  <th className="py-2.5 px-3">MITRE</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06] text-xs">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-10 text-center text-zinc-500">
                      No incidents match the current filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => {
                    const sevStyle = getSeverityMarker(alert.severity);
                    return (
                      <tr
                        key={alert.id}
                        onClick={() => onSelectAlert(alert)}
                        className="hover:bg-white/[0.03] transition-colors cursor-pointer"
                      >
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className={`inline-flex items-center gap-2 font-mono text-xs ${sevStyle.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-xs ${sevStyle.dot}`} />
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 whitespace-nowrap tabular-nums">
                          {alert.id}
                        </td>
                        <td className="py-2.5 px-3 max-w-[260px]">
                          <div className="font-medium text-zinc-100 truncate">{alert.title}</div>
                          <div className="text-[11px] font-mono text-zinc-500 truncate">
                            {alert.ruleMatched} · {alert.timestamp}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                          <div className="text-zinc-200">{alert.assetName}</div>
                          <div className="text-[11px] text-zinc-500 tabular-nums">{alert.sourceIp}</div>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 whitespace-nowrap">
                          {alert.mitreTechniqueId}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span
                            className={`text-xs font-mono ${
                              alert.status === 'Mitigated' || alert.status === 'Closed'
                                ? 'text-emerald-400'
                                : alert.status === 'Investigating'
                                ? 'text-amber-400'
                                : 'text-zinc-200'
                            }`}
                          >
                            {alert.status}
                          </span>
                        </td>
                        <td
                          className="py-2.5 px-4 text-right whitespace-nowrap"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              onClick={() => onSelectAlert(alert)}
                              className="h-7 px-2.5 bg-[#090B0F] hover:bg-white/[0.06] text-zinc-300 border border-white/[0.08] rounded text-[11px] font-medium inline-flex items-center gap-1 cursor-pointer"
                            >
                              <Eye className="w-3 h-3 text-zinc-400" />
                              <span>Triage</span>
                            </button>
                            {alert.recommendedPlaybookId && !alert.playbookExecuted ? (
                              <button
                                onClick={() => onExecutePlaybook(alert.recommendedPlaybookId!, alert.id)}
                                className="h-7 px-2.5 bg-blue-600/15 hover:bg-blue-600/25 text-blue-400 border border-blue-500/30 rounded text-[11px] font-medium inline-flex items-center gap-1 cursor-pointer"
                              >
                                <Play className="w-3 h-3" />
                                <span>Mitigate</span>
                              </button>
                            ) : (
                              <span className="h-7 px-2 text-emerald-400 text-[11px] font-mono inline-flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Done</span>
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: SOAR Playbooks + Fleet Posture */}
        <div className="space-y-6">
          {/* Playbooks */}
          <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg">
            <div className="px-4 py-3 border-b border-white/[0.08] flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">Response Playbooks</h2>
              <button
                onClick={() => onNavigateTab('defender')}
                className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 cursor-pointer"
              >
                <span>Configure</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="divide-y divide-white/[0.06]">
              {playbooks.map((pb) => (
                <div key={pb.id} className="p-4 flex items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-zinc-100 truncate">{pb.name}</span>
                    </div>
                    <div className="text-[11px] font-mono text-zinc-500">
                      {pb.category} · {pb.autoTriggerEnabled ? 'Auto-armed' : 'Manual'} · {pb.executionCount} runs
                    </div>
                  </div>
                  <button
                    onClick={() => onExecutePlaybook(pb.id)}
                    className="h-7 px-2.5 bg-[#090B0F] hover:bg-white/[0.06] text-zinc-200 border border-white/[0.08] rounded text-[11px] font-medium shrink-0 cursor-pointer"
                  >
                    Run
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Fleet Posture Summary */}
          <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg">
            <div className="px-4 py-3 border-b border-white/[0.08] flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">Critical Workloads</h2>
              <button
                onClick={() => onNavigateTab('topology')}
                className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 cursor-pointer"
              >
                <span>Inventory</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="divide-y divide-white/[0.06]">
              {assets.slice(0, 5).map((ast) => (
                <div key={ast.id} className="px-4 py-2.5 flex items-center justify-between text-xs">
                  <div className="min-w-0">
                    <div className="font-mono text-zinc-200 truncate">{ast.name}</div>
                    <div className="font-mono text-[11px] text-zinc-500 tabular-nums">
                      {ast.ip} · Risk {ast.riskScore}/100
                    </div>
                  </div>
                  <span
                    className={`font-mono text-[11px] shrink-0 ${
                      ast.status === 'Protected'
                        ? 'text-emerald-400'
                        : ast.status === 'At Risk'
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}
                  >
                    {ast.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
