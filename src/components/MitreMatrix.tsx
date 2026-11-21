import React, { useState, useEffect } from 'react';
import { Search, ShieldCheck } from 'lucide-react';
import { MitreTechnique } from '../types';

interface MitreMatrixProps {
  tacticsData: MitreTechnique[];
  initialIntelQuery?: string;
}

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ tacticsData, initialIntelQuery }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(tacticsData[0] || null);
  const [intelQuery, setIntelQuery] = useState<string>(initialIntelQuery || '');
  const [intelResult, setIntelResult] = useState<any | null>(null);
  const [intelLoading, setIntelLoading] = useState<boolean>(false);

  const runLookup = async (q: string) => {
    if (!q.trim()) return;
    setIntelLoading(true);
    try {
      const res = await fetch('/api/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q.trim() }),
      });
      const data = await res.json();
      setIntelResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIntelLoading(false);
    }
  };

  useEffect(() => {
    if (initialIntelQuery) {
      setIntelQuery(initialIntelQuery);
      runLookup(initialIntelQuery);
    }
  }, [initialIntelQuery]);

  const handleIntelLookup = (e: React.FormEvent) => {
    e.preventDefault();
    runLookup(intelQuery);
  };

  const getStatusColor = (status: MitreTechnique['detectionStatus']) => {
    switch (status) {
      case 'Blocked':
        return 'text-emerald-400';
      case 'Detected':
        return 'text-amber-400';
      case 'Tested':
        return 'text-sky-400';
      default:
        return 'text-zinc-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header + Live RDAP/DNS IOC Enrichment */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">
            MITRE ATT&amp;CK Coverage &amp; IOC Enrichment
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Adversary technique coverage matrix and live DNS / RDAP network ownership lookups.
          </p>
        </div>

        <form onSubmit={handleIntelLookup} className="flex items-center gap-2 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="IP, domain, or SHA-256..."
              value={intelQuery}
              onChange={(e) => setIntelQuery(e.target.value)}
              className="h-8 bg-[#0E1117] border border-white/[0.08] text-xs text-zinc-200 rounded-md pl-8 pr-3 font-mono w-56 focus:outline-none focus:border-blue-500/60"
            />
          </div>
          <button
            type="submit"
            disabled={intelLoading}
            className="h-8 px-3.5 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
          >
            {intelLoading ? 'Querying...' : 'Enrich IOC'}
          </button>
        </form>
      </div>

      {/* Live RDAP / DNS Result */}
      {intelResult && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] pb-2.5 text-xs font-mono">
            <span className="text-white font-medium">
              IOC Enrichment: {intelResult.query} ({intelResult.type})
            </span>
            <span className={intelResult.threatScore >= 70 ? 'text-rose-400' : 'text-zinc-400'}>
              {intelResult.reputation} · Score {intelResult.threatScore}/100
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
            <div>
              <div className="text-[11px] text-zinc-500">Internal Incident Hits</div>
              <div className="text-zinc-200 mt-0.5">
                {intelResult.internalTelemetryHits?.length > 0
                  ? intelResult.internalTelemetryHits.join(', ')
                  : 'None observed'}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-zinc-500">DNS / Reverse PTR</div>
              <div className="text-zinc-200 mt-0.5 truncate">
                {intelResult.reversePtr?.length > 0
                  ? intelResult.reversePtr.join(', ')
                  : intelResult.resolvedIps?.length > 0
                  ? intelResult.resolvedIps.join(', ')
                  : 'No PTR/A record'}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-zinc-500">RDAP Network / Registrar</div>
              <div className="text-zinc-200 mt-0.5 truncate">
                {intelResult.registry ? `${intelResult.registry.name} (${intelResult.registry.country})` : 'Unavailable'}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-zinc-500">CIDR / Handle</div>
              <div className="text-zinc-200 mt-0.5 truncate">
                {intelResult.registry?.cidr || intelResult.registry?.handle || '—'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Technique Coverage Matrix */}
      <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Enterprise Technique Matrix</h2>
          <span className="text-xs font-mono text-zinc-500 tabular-nums">
            {tacticsData.filter((t) => t.detectionStatus !== 'Uncovered').length}/{tacticsData.length} covered
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5">
          {tacticsData.map((tech) => {
            const isSelected = selectedTechnique?.id === tech.id;
            return (
              <button
                key={tech.id}
                onClick={() => setSelectedTechnique(tech)}
                className={`text-left bg-[#090B0F] border rounded-md p-3 transition-colors cursor-pointer flex flex-col justify-between space-y-2 ${
                  isSelected
                    ? 'border-blue-500 bg-white/[0.04]'
                    : 'border-white/[0.08] hover:border-white/20'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-zinc-400">{tech.id}</span>
                    <span className={getStatusColor(tech.detectionStatus)}>{tech.detectionStatus}</span>
                  </div>
                  <div className="text-xs font-medium text-zinc-100 mt-1 line-clamp-2">{tech.name}</div>
                </div>
                <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between text-[11px] font-mono text-zinc-500">
                  <span className="truncate">{tech.tactic}</span>
                  {tech.activeAlertsCount > 0 && (
                    <span className="text-rose-400 tabular-nums shrink-0">{tech.activeAlertsCount}</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Technique Inspector */}
      {selectedTechnique && (
        <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] pb-3">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-mono text-blue-400">{selectedTechnique.id}</span>
              <h2 className="text-sm font-semibold text-white">{selectedTechnique.name}</h2>
            </div>
            <span className="text-xs font-mono text-zinc-400">
              Tactic: {selectedTechnique.tactic} · Status:{' '}
              <span className={getStatusColor(selectedTechnique.detectionStatus)}>
                {selectedTechnique.detectionStatus}
              </span>
            </span>
          </div>

          <p className="text-xs text-zinc-300 leading-relaxed">{selectedTechnique.description}</p>

          <div className="bg-[#090B0F] border border-white/[0.08] rounded-md p-3 flex flex-wrap items-center gap-6 text-xs font-mono text-zinc-300">
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Sigma: SIGMA-ENT-{selectedTechnique.id.replace('.', '_')}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              Suricata: ET-ATTK-{selectedTechnique.id.replace('.', '_')}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
