import React, { useState } from 'react';
import { Send, Copy, Check, Download } from 'lucide-react';
import { CopilotMessage, UserRole } from '../types';

interface SentinelCopilotProps {
  role: UserRole;
  onRefreshState: () => Promise<void>;
}

export const SentinelCopilot: React.FC<SentinelCopilotProps> = ({ role }) => {
  const [activeTab, setActiveTab] = useState<'copilot' | 'rulegen' | 'reports'>('copilot');

  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: 'msg-init',
      sender: 'assistant',
      text: `Ready for incident triage (${role}). Queries are grounded against live workspace incidents, asset inventory, and active detection rules.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);

  // Rule Synthesizer
  const [ruleType, setRuleType] = useState<'sigma' | 'yara' | 'suricata'>('sigma');
  const [ruleDescription, setRuleDescription] = useState(
    'Detect encoded PowerShell download cradle spawning from office process'
  );
  const [generatedRule, setGeneratedRule] = useState<string>('');
  const [ruleLoading, setRuleLoading] = useState(false);

  // Report Compiler
  const [reportType, setReportType] = useState('Executive CISO Summary');
  const [generatedReport, setGeneratedReport] = useState<string>('');
  const [reportLoading, setReportLoading] = useState(false);

  const [copied, setCopied] = useState(false);

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || inputText;
    if (!query.trim() || loading) return;

    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInputText('');
    setLoading(true);

    try {
      const res = await fetch('/api/ai/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: query, role }),
      });
      const data = await res.json();

      setMessages((prev) => [
        ...prev,
        {
          id: `msg-${Date.now() + 1}`,
          sender: 'assistant',
          text: data.analysis || data.error || 'No analysis returned.',
          model: data.model,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          explainability: data.explainability,
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `msg-${Date.now() + 1}`,
          sender: 'assistant',
          text: `Request failed: ${err.message}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateRule = async () => {
    setRuleLoading(true);
    try {
      const res = await fetch('/api/ai/generate-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleType, description: ruleDescription }),
      });
      const data = await res.json();
      setGeneratedRule(data.rule || data.error || '');
    } finally {
      setRuleLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    setReportLoading(true);
    try {
      const res = await fetch('/api/ai/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportType }),
      });
      const data = await res.json();
      setGeneratedReport(data.report || data.error || '');
    } finally {
      setReportLoading(false);
    }
  };

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const downloadMarkdown = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">Security Copilot</h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Incident triage assistant, Sigma/YARA rule synthesis, and audit report compilation backed by live workspace telemetry.
          </p>
        </div>

        <div className="inline-flex items-center p-1 bg-[#0E1117] border border-white/[0.08] rounded-md shrink-0">
          {([
            { id: 'copilot', label: 'Triage Assistant' },
            { id: 'rulegen', label: 'Rule Synthesis' },
            { id: 'reports', label: 'Report Compiler' },
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === t.id ? 'bg-white/[0.09] text-white' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab 1: Triage Assistant */}
      {activeTab === 'copilot' && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg flex flex-col h-[580px]">
          <div className="px-4 py-2.5 border-b border-white/[0.08] flex flex-wrap items-center gap-2 text-[11px] font-mono">
            <span className="text-zinc-500">Prompts:</span>
            {[
              'Triage INC-4091 on prod-db-01',
              'Summarize open critical exposure and containment steps',
              'Draft remediation plan for CIS 5.2.1 on bastion-gw-01',
            ].map((q) => (
              <button
                key={q}
                onClick={() => handleSendMessage(q)}
                className="px-2.5 py-1 bg-[#090B0F] hover:bg-white/[0.05] border border-white/[0.08] rounded text-zinc-300 cursor-pointer"
              >
                {q}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div className="text-[11px] font-mono text-zinc-500 mb-1">
                  {msg.sender === 'user' ? role : 'Sentinel Copilot'} · {msg.timestamp}
                </div>
                <div
                  className={`max-w-3xl rounded-md p-3.5 text-xs leading-relaxed border ${
                    msg.sender === 'user'
                      ? 'bg-blue-600/15 border-blue-500/30 text-zinc-100'
                      : 'bg-[#090B0F] border-white/[0.08] text-zinc-200'
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.text}</div>
                  {msg.explainability && (
                    <div className="mt-3 pt-2.5 border-t border-white/[0.08] text-[11px] font-mono text-zinc-400 space-y-1">
                      <div>
                        Confidence: <span className="text-zinc-200">{msg.explainability.confidenceScore}%</span> ·
                        Rules: <span className="text-zinc-200">{msg.explainability.ruleMatches.join(', ')}</span>
                      </div>
                      <div className="text-zinc-500">
                        {msg.explainability.evidenceFactors.join(' · ')}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div className="text-xs font-mono text-zinc-400">Querying workspace context...</div>
            )}
          </div>

          <div className="p-3 border-t border-white/[0.08] flex items-center gap-2">
            <input
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              placeholder="Ask about an incident ID, CVE, Sigma pattern, or containment strategy..."
              className="flex-1 h-9 bg-[#090B0F] border border-white/[0.08] rounded-md px-3 text-xs font-mono text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-blue-500/70"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={loading || !inputText.trim()}
              className="h-9 px-3.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-md inline-flex items-center gap-1.5 text-xs font-medium cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </div>
        </div>
      )}

      {/* Tab 2: Rule Synthesis */}
      {activeTab === 'rulegen' && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-[11px] text-zinc-500 mb-1">Syntax Format</label>
              <select
                value={ruleType}
                onChange={(e) => setRuleType(e.target.value as any)}
                className="w-full h-9 bg-[#090B0F] border border-white/[0.08] rounded-md px-3 text-xs font-mono text-zinc-200 focus:outline-none"
              >
                <option value="sigma">Sigma YAML</option>
                <option value="yara">YARA Signature</option>
                <option value="suricata">Suricata IDS</option>
              </select>
            </div>
            <div className="md:col-span-3">
              <label className="block text-[11px] text-zinc-500 mb-1">Behavior / Indicator Specification</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={ruleDescription}
                  onChange={(e) => setRuleDescription(e.target.value)}
                  className="flex-1 h-9 bg-[#090B0F] border border-white/[0.08] rounded-md px-3 text-xs font-mono text-zinc-200 focus:outline-none focus:border-blue-500/70"
                />
                <button
                  onClick={handleGenerateRule}
                  disabled={ruleLoading}
                  className="h-9 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium rounded-md cursor-pointer whitespace-nowrap"
                >
                  {ruleLoading ? 'Synthesizing...' : 'Generate Rule'}
                </button>
              </div>
            </div>
          </div>

          {generatedRule && (
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
                <span>Output ({ruleType.toUpperCase()})</span>
                <button
                  onClick={() => copyText(generatedRule)}
                  className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="bg-[#090B0F] border border-white/[0.08] rounded-md p-4 text-xs font-mono text-zinc-200 overflow-x-auto">
                {generatedRule}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Report Compiler */}
      {activeTab === 'reports' && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-5 space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="block text-[11px] text-zinc-500 mb-1">Report Template</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="h-9 bg-[#090B0F] border border-white/[0.08] rounded-md px-3 text-xs text-zinc-200 focus:outline-none cursor-pointer"
              >
                <option value="Executive CISO Summary">Executive CISO Summary</option>
                <option value="Incident Post-Mortem">Incident Post-Mortem</option>
                <option value="Compliance Gap Assessment">Compliance Gap Assessment</option>
              </select>
            </div>
            <button
              onClick={handleGenerateReport}
              disabled={reportLoading}
              className="h-9 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium rounded-md cursor-pointer whitespace-nowrap"
            >
              {reportLoading ? 'Compiling...' : 'Compile Report'}
            </button>
          </div>

          {generatedReport && (
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
                <span>Markdown Brief</span>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => copyText(generatedReport)}
                    className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={() => downloadMarkdown(generatedReport, 'sentinel-security-report.md')}
                    className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .md</span>
                  </button>
                </div>
              </div>
              <pre className="bg-[#090B0F] border border-white/[0.08] rounded-md p-4 text-xs text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto font-sans">
                {generatedReport}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
