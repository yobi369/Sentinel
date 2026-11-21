import React, { useState } from 'react';
import { Download } from 'lucide-react';
import { ComplianceCheck } from '../types';

interface ComplianceAuditProps {
  complianceChecks: ComplianceCheck[];
}

export const ComplianceAudit: React.FC<ComplianceAuditProps> = ({ complianceChecks }) => {
  const [selectedFramework, setSelectedFramework] = useState<string>('ALL');

  const filteredChecks = complianceChecks.filter(
    (c) => selectedFramework === 'ALL' || c.framework === selectedFramework
  );

  const passCount = complianceChecks.filter((c) => c.status === 'PASS').length;
  const failCount = complianceChecks.filter((c) => c.status === 'FAIL').length;
  const warnCount = complianceChecks.filter((c) => c.status === 'WARN').length;
  const overallPercentage = Math.round((passCount / Math.max(complianceChecks.length, 1)) * 100);

  const handleExportCsv = () => {
    const header = 'ID,Framework,Control,Title,Status,Score,LastVerified,Remediation\n';
    const rows = filteredChecks
      .map(
        (c) =>
          `"${c.id}","${c.framework}","${c.controlId}","${c.title}","${c.status}",${c.score},"${c.lastVerified}","${c.remediation.replace(/"/g, '""')}"`
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-compliance-${selectedFramework.toLowerCase().replace(/\s+/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">
            Compliance &amp; Control Verification
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Continuous control attestation across NIST 800-53, CIS Benchmarks, PCI-DSS 4.0, and ISO 27001.
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          className="h-8 px-3 bg-[#0E1117] hover:bg-white/[0.05] text-zinc-200 border border-white/[0.08] rounded-md text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer shrink-0 whitespace-nowrap"
        >
          <Download className="w-3.5 h-3.5 text-zinc-400" />
          <span>Export CSV Evidence</span>
        </button>
      </div>

      {/* Summary Strip */}
      <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.08]">
        <div className="p-4">
          <div className="text-xs text-zinc-400">Overall Attestation</div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-white">
            {overallPercentage}%
          </div>
        </div>
        <div className="p-4">
          <div className="text-xs text-zinc-400">Passing Controls</div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-emerald-400">
            {passCount}
          </div>
        </div>
        <div className="p-4">
          <div className="text-xs text-zinc-400">Warnings</div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-amber-400">
            {warnCount}
          </div>
        </div>
        <div className="p-4">
          <div className="text-xs text-zinc-400">Failed Controls</div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-rose-400">
            {failCount}
          </div>
        </div>
      </div>

      {/* Filter Bar + Table */}
      <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/[0.08] flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-[#090B0F] border border-white/[0.08] rounded-md">
            {['ALL', 'NIST 800-53', 'CIS Benchmarks', 'PCI-DSS 4.0', 'ISO 27001'].map((fw) => (
              <button
                key={fw}
                onClick={() => setSelectedFramework(fw)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  selectedFramework === fw
                    ? 'bg-white/[0.09] text-white'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {fw === 'ALL' ? 'All Frameworks' : fw}
              </button>
            ))}
          </div>
          <span className="text-xs font-mono text-zinc-500 tabular-nums">
            {filteredChecks.length} controls
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500">
                <th className="py-2.5 px-4">Framework</th>
                <th className="py-2.5 px-3">Control</th>
                <th className="py-2.5 px-3">Requirement &amp; Evidence</th>
                <th className="py-2.5 px-3">Score</th>
                <th className="py-2.5 px-3">Verified</th>
                <th className="py-2.5 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-xs">
              {filteredChecks.map((item) => (
                <tr key={item.id} className="hover:bg-white/[0.03] align-top">
                  <td className="py-3 px-4 font-mono text-zinc-300 whitespace-nowrap">
                    {item.framework}
                  </td>
                  <td className="py-3 px-3 font-mono text-zinc-400 whitespace-nowrap">
                    {item.controlId}
                  </td>
                  <td className="py-3 px-3 space-y-1 max-w-xl">
                    <div className="font-medium text-zinc-100">{item.title}</div>
                    <div className="text-zinc-400 leading-relaxed">{item.details}</div>
                    {item.status !== 'PASS' && (
                      <div className="font-mono text-[11px] text-amber-300 pt-1">
                        Remediation: {item.remediation}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-3 font-mono tabular-nums text-zinc-300 whitespace-nowrap">
                    {item.score}%
                  </td>
                  <td className="py-3 px-3 font-mono tabular-nums text-zinc-500 whitespace-nowrap">
                    {item.lastVerified}
                  </td>
                  <td className="py-3 px-4 text-right font-mono whitespace-nowrap">
                    <span
                      className={
                        item.status === 'PASS'
                          ? 'text-emerald-400'
                          : item.status === 'FAIL'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }
                    >
                      {item.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
