import React, { useState } from 'react';
import { Play, Plus, Search, CheckCircle2, AlertCircle } from 'lucide-react';
import { Playbook, DetectionRule, TelemetryEvent, Severity } from '../types';

interface DefenderAIProps {
  playbooks: Playbook[];
  rules: DetectionRule[];
  telemetry: TelemetryEvent[];
  onExecutePlaybook: (playbookId: string) => void;
  onToggleAutoTrigger: (playbookId: string, nextVal: boolean) => void;
  onToggleRule: (ruleId: string, enabled: boolean) => void;
  onCreateRule: (payload: {
    title: string;
    format: 'sigma' | 'yara' | 'suricata';
    target: string;
    severity: Severity;
    pattern: string;
    mitreId: string;
  }) => Promise<void>;
  onIngestLog: (source: string, host: string, raw: string) => Promise<void>;
}

export const DefenderAI: React.FC<DefenderAIProps> = ({
  playbooks,
  rules,
  telemetry,
  onExecutePlaybook,
  onToggleAutoTrigger,
  onToggleRule,
  onCreateRule,
  onIngestLog,
}) => {
  const [activeTab, setActiveTab] = useState<'rules' | 'playbooks' | 'telemetry'>('rules');
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(rules[0] || null);

  // Live Rule Tester State
  const [testPattern, setTestPattern] = useState<string>(rules[0]?.pattern || 'powershell\\.exe');
  const [testResult, setTestResult] = useState<{
    valid: boolean;
    scannedCount: number;
    matchCount: number;
    durationMs: number;
    matches: TelemetryEvent[];
  } | null>(null);
  const [testError, setTestError] = useState<string>('');
  const [testing, setTesting] = useState(false);

  // New Rule Form
  const [showNewRuleForm, setShowNewRuleForm] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newFormat, setNewFormat] = useState<'sigma' | 'yara' | 'suricata'>('sigma');
  const [newSeverity, setNewSeverity] = useState<Severity>('High');
  const [newPattern, setNewPattern] = useState('');
  const [newMitre, setNewMitre] = useState('T1059');

  // Quick Ingest on Telemetry tab
  const [logSource, setLogSource] = useState('syslog');
  const [logHost, setLogHost] = useState('app-worker-04');
  const [logRaw, setLogRaw] = useState('');

  const handleSelectRule = (rule: DetectionRule) => {
    setSelectedRule(rule);
    setTestPattern(rule.pattern);
    setTestResult(null);
    setTestError('');
  };

  const handleRunRuleTest = async () => {
    if (!testPattern.trim()) return;
    setTesting(true);
    setTestError('');
    try {
      const res = await fetch('/api/rules/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: testPattern }),
      });
      const data = await res.json();
      if (!res.ok) {
        setTestError(data.error || 'Pattern validation failed');
        setTestResult(null);
      } else {
        setTestResult(data);
      }
    } catch (err: any) {
      setTestError(err.message);
    } finally {
      setTesting(false);
    }
  };

  const handleDeployRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newPattern.trim()) return;
    await onCreateRule({
      title: newTitle.trim(),
      format: newFormat,
      target: 'Live Telemetry Stream',
      severity: newSeverity,
      pattern: newPattern.trim(),
      mitreId: newMitre.trim() || 'T1059',
    });
    setNewTitle('');
    setNewPattern('');
    setShowNewRuleForm(false);
  };

  const handleQuickIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!logRaw.trim()) return;
    await onIngestLog(logSource, logHost, logRaw);
    setLogRaw('');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">Detection Engineering &amp; SOAR</h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Manage regex-backed detection patterns and inspect telemetry. Sigma/YARA/Suricata native engines and external response execution are not yet integrated.
          </p>
        </div>

        {/* Segmented Control */}
        <div className="inline-flex items-center p-1 bg-[#0E1117] border border-white/[0.08] rounded-md shrink-0">
          {([
            { id: 'rules', label: `Detection Rules (${rules.length})` },
            { id: 'playbooks', label: `Playbooks (${playbooks.length})` },
            { id: 'telemetry', label: `Telemetry (${telemetry.length})` },
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === t.id
                  ? 'bg-white/[0.09] text-white'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab 1: Detection Engineering & Live Tester */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-400">
              Select a rule to inspect syntax or test a custom regex signature directly against ingested telemetry.
            </span>
            <button
              onClick={() => setShowNewRuleForm((v) => !v)}
              className="h-8 px-3 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Deploy Custom Rule</span>
            </button>
          </div>

          {showNewRuleForm && (
            <form
              onSubmit={handleDeployRule}
              className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 grid grid-cols-1 md:grid-cols-6 gap-3"
            >
              <div className="md:col-span-2">
                <label className="block text-[11px] text-zinc-500 mb-1">Rule Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Reverse Shell Pipe to Bash"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2.5 text-xs text-zinc-200 focus:outline-none focus:border-blue-500/60"
                />
              </div>
              <div>
                <label className="block text-[11px] text-zinc-500 mb-1">Format</label>
                <select
                  value={newFormat}
                  onChange={(e) => setNewFormat(e.target.value as any)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2 text-xs font-mono text-zinc-200 focus:outline-none"
                >
                  <option value="sigma">Sigma</option>
                  <option value="yara">YARA</option>
                  <option value="suricata">Suricata</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] text-zinc-500 mb-1">Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as Severity)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2 text-xs text-zinc-200 focus:outline-none"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] text-zinc-500 mb-1">MITRE ID</label>
                <input
                  type="text"
                  value={newMitre}
                  onChange={(e) => setNewMitre(e.target.value)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2.5 text-xs font-mono text-zinc-200 focus:outline-none"
                />
              </div>
              <div className="flex items-end">
                <button
                  type="submit"
                  className="w-full h-8 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded cursor-pointer"
                >
                  Save &amp; Arm Rule
                </button>
              </div>
              <div className="md:col-span-6">
                <label className="block text-[11px] text-zinc-500 mb-1">Detection Regex Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. (curl|wget).*\|\s*(bash|sh)"
                  value={newPattern}
                  onChange={(e) => setNewPattern(e.target.value)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-blue-500/60"
                />
              </div>
            </form>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            {/* Rules Table (3 cols) */}
            <div className="lg:col-span-3 bg-[#0E1117] border border-white/[0.08] rounded-lg overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500">
                    <th className="py-2.5 px-4">Rule ID</th>
                    <th className="py-2.5 px-3">Title</th>
                    <th className="py-2.5 px-3">Format</th>
                    <th className="py-2.5 px-3">Hits</th>
                    <th className="py-2.5 px-4 text-right">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06] text-xs">
                  {rules.map((rule) => {
                    const isSelected = selectedRule?.id === rule.id;
                    return (
                      <tr
                        key={rule.id}
                        onClick={() => handleSelectRule(rule)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-white/[0.06]' : 'hover:bg-white/[0.03]'
                        }`}
                      >
                        <td className="py-2.5 px-4 font-mono text-zinc-300 whitespace-nowrap">{rule.id}</td>
                        <td className="py-2.5 px-3">
                          <div className="font-medium text-zinc-100">{rule.title}</div>
                          <div className="text-[11px] font-mono text-zinc-500">
                            {rule.mitreId} · {rule.severity}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono uppercase text-zinc-400">{rule.format}</td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-zinc-300">{rule.matchCount}</td>
                        <td
                          className="py-2.5 px-4 text-right whitespace-nowrap"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            onClick={() => onToggleRule(rule.id, !rule.enabled)}
                            className={`text-xs font-mono cursor-pointer ${
                              rule.enabled ? 'text-emerald-400' : 'text-zinc-500'
                            }`}
                          >
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Rule Definition & Live Pattern Bench (2 cols) */}
            <div className="lg:col-span-2 bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 space-y-4">
              {selectedRule && (
                <>
                  <div className="border-b border-white/[0.08] pb-3">
                    <div className="text-xs font-mono text-blue-400">{selectedRule.id}</div>
                    <h3 className="text-sm font-semibold text-white mt-0.5">{selectedRule.title}</h3>
                    <div className="text-[11px] font-mono text-zinc-500 mt-1">
                      Target: {selectedRule.target} · MITRE: {selectedRule.mitreId}
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] font-medium text-zinc-400 mb-1.5">Rule Definition</div>
                    <pre className="bg-[#090B0F] border border-white/[0.08] rounded-md p-3 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-48">
                      {selectedRule.code}
                    </pre>
                  </div>

                  {/* Live Pattern Tester */}
                  <div className="pt-2 border-t border-white/[0.08] space-y-2.5">
                    <div className="text-xs font-medium text-zinc-200">Live Telemetry Pattern Benchmark</div>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={testPattern}
                        onChange={(e) => setTestPattern(e.target.value)}
                        placeholder="Regex pattern..."
                        className="flex-1 h-8 bg-[#090B0F] border border-white/[0.08] rounded-md px-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-blue-500/60"
                      />
                      <button
                        onClick={handleRunRuleTest}
                        disabled={testing}
                        className="h-8 px-3 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md cursor-pointer disabled:opacity-50 whitespace-nowrap"
                      >
                        {testing ? 'Testing...' : 'Run Query'}
                      </button>
                    </div>

                    {testError && (
                      <div className="text-xs font-mono text-rose-400 flex items-center gap-1.5">
                        <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                        <span>{testError}</span>
                      </div>
                    )}

                    {testResult && (
                      <div className="bg-[#090B0F] border border-white/[0.08] rounded-md p-3 space-y-2">
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <span className="text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {testResult.matchCount} / {testResult.scannedCount} events matched
                          </span>
                          <span className="text-zinc-500 tabular-nums">{testResult.durationMs} ms</span>
                        </div>
                        {testResult.matches.length > 0 && (
                          <div className="space-y-1.5 max-h-32 overflow-y-auto pt-1 border-t border-white/[0.06]">
                            {testResult.matches.map((m) => (
                              <div key={m.id} className="text-[11px] font-mono text-zinc-300 truncate" title={m.raw}>
                                [{m.host}] {m.raw}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Playbooks */}
      {activeTab === 'playbooks' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {playbooks.map((pb) => (
            <div
              key={pb.id}
              className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-5 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-zinc-500">
                    {pb.id} · {pb.category}
                  </span>
                  <button
                    onClick={() => onToggleAutoTrigger(pb.id, !pb.autoTriggerEnabled)}
                    className={`text-xs font-mono cursor-pointer ${
                      pb.autoTriggerEnabled ? 'text-emerald-400' : 'text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    {pb.autoTriggerEnabled ? 'Auto-Trigger: Armed' : 'Auto-Trigger: Manual'}
                  </button>
                </div>

                <div>
                  <h2 className="text-sm font-semibold text-white">{pb.name}</h2>
                  <p className="text-xs text-zinc-400 mt-1 leading-relaxed">{pb.description}</p>
                </div>

                <ol className="space-y-1.5 pt-2 border-t border-white/[0.06] text-xs text-zinc-300">
                  {pb.actionSteps.map((step, idx) => (
                    <li key={idx} className="flex items-baseline gap-2.5">
                      <span className="font-mono text-[11px] text-zinc-500 tabular-nums">
                        {String(idx + 1).padStart(2, '0')}.
                      </span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>

              <div className="pt-3 border-t border-white/[0.08] flex items-center justify-between text-xs">
                <span className="font-mono text-zinc-500 tabular-nums">
                  {pb.executionCount} executions
                  {pb.lastExecutedAt ? ` · Last ${pb.lastExecutedAt}` : ''}
                </span>
                <button
                  onClick={() => onExecutePlaybook(pb.id)}
                  className="h-8 px-3 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Play className="w-3 h-3" />
                  <span>Execute</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Live Telemetry Stream */}
      {activeTab === 'telemetry' && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg overflow-hidden">
          <form
            onSubmit={handleQuickIngest}
            className="p-3 border-b border-white/[0.08] flex flex-wrap items-center gap-2 bg-[#090B0F]/60"
          >
            <select
              value={logSource}
              onChange={(e) => setLogSource(e.target.value)}
              className="h-8 bg-[#0E1117] border border-white/[0.08] rounded px-2 text-xs font-mono text-zinc-300 focus:outline-none"
            >
              <option value="syslog">syslog</option>
              <option value="suricata">suricata</option>
              <option value="zeek">zeek</option>
              <option value="edr">edr</option>
            </select>
            <input
              type="text"
              value={logHost}
              onChange={(e) => setLogHost(e.target.value)}
              placeholder="Host"
              className="h-8 w-36 bg-[#0E1117] border border-white/[0.08] rounded px-2.5 text-xs font-mono text-zinc-200 focus:outline-none"
            />
            <input
              type="text"
              value={logRaw}
              onChange={(e) => setLogRaw(e.target.value)}
              placeholder="Paste raw syslog, Suricata alert, or Sysmon command line to evaluate..."
              className="flex-1 min-w-[240px] h-8 bg-[#0E1117] border border-white/[0.08] rounded px-3 text-xs font-mono text-zinc-200 focus:outline-none focus:border-blue-500/60"
            />
            <button
              type="submit"
              className="h-8 px-3.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded cursor-pointer whitespace-nowrap"
            >
              Ingest Event
            </button>
          </form>

          <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500">
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-3">Source</th>
                  <th className="py-2.5 px-3">Host</th>
                  <th className="py-2.5 px-3">Rule Match</th>
                  <th className="py-2.5 px-4">Raw Telemetry</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06] text-xs font-mono">
                {telemetry.map((evt) => (
                  <tr key={evt.id} className="hover:bg-white/[0.03]">
                    <td className="py-2 px-4 text-zinc-400 whitespace-nowrap tabular-nums">
                      {evt.timestamp.replace('T', ' ').substring(0, 19)}
                    </td>
                    <td className="py-2 px-3 text-zinc-300 whitespace-nowrap">{evt.source}</td>
                    <td className="py-2 px-3 text-zinc-200 whitespace-nowrap">{evt.host}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {evt.matchedRuleId ? (
                        <span className="text-rose-400">{evt.matchedRuleId}</span>
                      ) : (
                        <span className="text-zinc-600">—</span>
                      )}
                    </td>
                    <td className="py-2 px-4 text-zinc-300 max-w-xl truncate" title={evt.raw}>
                      {evt.raw}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
