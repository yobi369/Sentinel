import React, { useState, useEffect } from 'react';
import { X, Play, CheckCircle2 } from 'lucide-react';
import { IncidentAlert } from '../types';

interface IncidentDetailModalProps {
  alert: IncidentAlert | null;
  onClose: () => void;
  onExecutePlaybook: (playbookId: string, alertId: string) => void;
  onUpdateAlert: (
    alertId: string,
    updates: { status?: IncidentAlert['status']; assignee?: string; triageNotes?: string }
  ) => Promise<void>;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  alert,
  onClose,
  onExecutePlaybook,
  onUpdateAlert,
}) => {
  const [status, setStatus] = useState<IncidentAlert['status']>('Active');
  const [assignee, setAssignee] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (alert) {
      setStatus(alert.status);
      setAssignee(alert.assignee || 'Unassigned');
      setNotes(alert.triageNotes || '');
    }
  }, [alert]);

  if (!alert) return null;

  const handleSaveTriage = async () => {
    setSaving(true);
    try {
      await onUpdateAlert(alert.id, { status, assignee, triageNotes: notes });
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0E1117] border border-white/[0.1] rounded-lg w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-white/[0.08] flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
              <span
                className={
                  alert.severity === 'Critical'
                    ? 'text-rose-400'
                    : alert.severity === 'High'
                    ? 'text-amber-400'
                    : 'text-sky-400'
                }
              >
                {alert.severity}
              </span>
              <span>·</span>
              <span>{alert.id}</span>
              <span>·</span>
              <span className="tabular-nums">{alert.timestamp}</span>
            </div>
            <h2 className="text-base font-semibold text-white mt-1">{alert.title}</h2>
          </div>

          <button onClick={onClose} className="text-zinc-400 hover:text-white cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Key Metadata Strip */}
          <div className="grid grid-cols-3 gap-4 border-b border-white/[0.08] pb-4 text-xs font-mono">
            <div>
              <div className="text-zinc-500 text-[11px]">Target Workload</div>
              <div className="text-zinc-100 mt-0.5">{alert.assetName}</div>
            </div>
            <div>
              <div className="text-zinc-500 text-[11px]">Source IP</div>
              <div className="text-rose-400 mt-0.5 tabular-nums">{alert.sourceIp}</div>
            </div>
            <div>
              <div className="text-zinc-500 text-[11px]">MITRE ATT&amp;CK</div>
              <div className="text-zinc-200 mt-0.5">{alert.mitreTechniqueId}</div>
            </div>
          </div>

          {/* Description & Raw Log */}
          <div className="space-y-2">
            <div className="text-xs font-medium text-zinc-400">Detection Summary</div>
            <p className="text-xs text-zinc-200 leading-relaxed">{alert.description}</p>
          </div>

          <div className="space-y-1.5">
            <div className="text-xs font-medium text-zinc-400">Raw Telemetry Event</div>
            <pre className="bg-[#090B0F] border border-white/[0.08] rounded-md p-3 text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre-wrap">
              {alert.rawLog}
            </pre>
          </div>

          {/* XAI Evidence Breakdown */}
          <div className="bg-[#090B0F] border border-white/[0.08] rounded-md p-4 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between text-zinc-300">
              <span>Explainability Rationale ({alert.ruleMatched})</span>
              <span className="text-zinc-400 tabular-nums">
                Confidence {alert.xaiExplanation.confidenceScore}% · FP Risk{' '}
                {alert.xaiExplanation.falsePositiveProbability}
              </span>
            </div>
            <ul className="list-disc list-inside space-y-1 text-[11px] text-zinc-400">
              {alert.xaiExplanation.evidenceFactors.map((ef, i) => (
                <li key={i}>{ef}</li>
              ))}
            </ul>
          </div>

          {/* Persistent Analyst Triage Form */}
          <div className="pt-2 border-t border-white/[0.08] space-y-3">
            <div className="text-xs font-medium text-white">Analyst Triage &amp; Notes</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] text-zinc-500 mb-1">Incident Status</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value as IncidentAlert['status'])}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2.5 text-xs text-zinc-200 focus:outline-none"
                >
                  <option value="Active">Active</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Mitigated">Mitigated</option>
                  <option value="Closed">Closed</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] text-zinc-500 mb-1">Assignee</label>
                <input
                  type="text"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  className="w-full h-8 bg-[#090B0F] border border-white/[0.08] rounded px-2.5 text-xs font-mono text-zinc-200 focus:outline-none"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] text-zinc-500 mb-1">Investigation Notes</label>
              <textarea
                rows={2}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Document host containment checks, ticket IDs, or IOC findings..."
                className="w-full bg-[#090B0F] border border-white/[0.08] rounded p-2.5 text-xs text-zinc-200 focus:outline-none focus:border-blue-500/60"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-white/[0.08] bg-[#090B0F] flex flex-wrap items-center justify-between gap-3">
          <div>
            {alert.recommendedPlaybookId && !alert.playbookExecuted ? (
              <button
                onClick={() => {
                  onExecutePlaybook(alert.recommendedPlaybookId!, alert.id);
                  onClose();
                }}
                className="h-8 px-3 bg-rose-600/90 hover:bg-rose-500 text-white text-xs font-medium rounded-md inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Execute Containment Playbook</span>
              </button>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Playbook Executed</span>
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="h-8 px-3 bg-transparent hover:bg-white/[0.05] text-zinc-300 text-xs font-medium rounded-md cursor-pointer"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveTriage}
              disabled={saving}
              className="h-8 px-4 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-md cursor-pointer disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Triage'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
