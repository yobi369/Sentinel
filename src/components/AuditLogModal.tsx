import React, { useState } from 'react';
import { X, ShieldCheck, AlertCircle } from 'lucide-react';
import { AuditLogEntry } from '../types';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
  logs: AuditLogEntry[];
  auditValid: boolean;
}

export const AuditLogModal: React.FC<AuditLogModalProps> = ({
  isOpen,
  onClose,
  logs,
  auditValid: initialValid,
}) => {
  const [verifying, setVerifying] = useState(false);
  const [verifyState, setVerifyState] = useState<{
    valid: boolean;
    checkedCount: number;
    headHash: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await fetch('/api/audit/verify');
      const data = await res.json();
      setVerifyState(data);
    } finally {
      setVerifying(false);
    }
  };

  const isValid = verifyState ? verifyState.valid : initialValid;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0E1117] border border-white/[0.1] rounded-lg w-full max-w-5xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-5 py-4 border-b border-white/[0.08] flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-white">Cryptographic Audit Ledger</h2>
            <span className="text-xs font-mono text-zinc-500">SHA-256 Hash Chain</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleVerifyChain}
              disabled={verifying}
              className="h-7 px-3 bg-[#090B0F] hover:bg-white/[0.05] border border-white/[0.08] rounded text-xs font-medium text-zinc-200 cursor-pointer"
            >
              {verifying ? 'Verifying...' : 'Verify Hash Chain'}
            </button>
            <button onClick={onClose} className="text-zinc-400 hover:text-white cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500 bg-[#090B0F] sticky top-0">
                <th className="py-2.5 px-4">Seq</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target</th>
                <th className="py-2.5 px-4">SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-xs font-mono">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-white/[0.02]">
                  <td className="py-2.5 px-4 text-zinc-500 tabular-nums">#{log.sequence}</td>
                  <td className="py-2.5 px-3 text-zinc-400 whitespace-nowrap tabular-nums">
                    {log.timestamp.replace('T', ' ').substring(0, 19)}
                  </td>
                  <td className="py-2.5 px-3 text-zinc-200 whitespace-nowrap">{log.actor}</td>
                  <td className="py-2.5 px-3 text-zinc-300 whitespace-nowrap">{log.action}</td>
                  <td className="py-2.5 px-3 text-zinc-400 max-w-xs truncate" title={log.target}>
                    {log.target}
                  </td>
                  <td className="py-2.5 px-4 text-zinc-500 max-w-[160px] truncate" title={log.hash}>
                    {log.hash}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-white/[0.08] flex items-center justify-between text-xs font-mono bg-[#090B0F]">
          <span className={`inline-flex items-center gap-1.5 ${isValid ? 'text-emerald-400' : 'text-rose-400'}`}>
            {isValid ? <ShieldCheck className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
            <span>
              {isValid
                ? `Chain Verified (${verifyState ? verifyState.checkedCount : logs.length} blocks intact)`
                : 'Chain integrity mismatch detected'}
            </span>
          </span>
          <button
            onClick={onClose}
            className="h-7 px-3 bg-white/[0.06] hover:bg-white/[0.1] text-zinc-200 rounded text-xs font-sans font-medium cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
