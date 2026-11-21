import React, { useState } from 'react';
import { Search, Server } from 'lucide-react';
import { Asset } from '../types';

interface AssetTopologyProps {
  assets: Asset[];
  onIsolateAsset: (assetId: string, restore?: boolean) => void;
}

export const AssetTopology: React.FC<AssetTopologyProps> = ({ assets, onIsolateAsset }) => {
  const [selectedSubnet, setSelectedSubnet] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');

  const subnets = ['ALL', ...Array.from(new Set(assets.map((a) => a.subnet)))];

  const filteredAssets = assets.filter((asset) => {
    const matchesSubnet = selectedSubnet === 'ALL' || asset.subnet === selectedSubnet;
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      asset.name.toLowerCase().includes(q) ||
      asset.ip.includes(q) ||
      asset.os.toLowerCase().includes(q);
    return matchesSubnet && matchesSearch;
  });

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || filteredAssets[0] || null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">
            Asset Inventory &amp; Network Segmentation
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Subnet workload inventory, open socket exposure, and eBPF host quarantine controls.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter hostname, IP, OS..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 bg-[#0E1117] border border-white/[0.08] rounded-md pl-8 pr-3 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-blue-500/60"
            />
          </div>
          <select
            value={selectedSubnet}
            onChange={(e) => setSelectedSubnet(e.target.value)}
            className="h-8 bg-[#0E1117] border border-white/[0.08] rounded-md px-2.5 text-xs font-mono text-zinc-300 focus:outline-none cursor-pointer"
          >
            {subnets.map((sub) => (
              <option key={sub} value={sub}>
                {sub === 'ALL' ? 'All subnets' : sub}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Subnet Segments Overview */}
      <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-white/[0.08]">
        {subnets
          .filter((s) => s !== 'ALL')
          .map((sub) => {
            const subAssets = assets.filter((a) => a.subnet === sub);
            return (
              <div key={sub} className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-zinc-200 font-medium">{sub}</span>
                  <span className="text-zinc-500 tabular-nums">{subAssets.length} hosts</span>
                </div>
                <div className="space-y-1.5">
                  {subAssets.map((ast) => (
                    <button
                      key={ast.id}
                      onClick={() => setSelectedAssetId(ast.id)}
                      className={`w-full text-left px-2.5 py-2 rounded border text-xs font-mono transition-colors cursor-pointer flex items-center justify-between ${
                        selectedAsset?.id === ast.id
                          ? 'bg-white/[0.06] border-blue-500/50 text-white'
                          : 'bg-[#090B0F] border-white/[0.06] text-zinc-300 hover:border-white/15'
                      }`}
                    >
                      <span className="truncate">{ast.name}</span>
                      <span
                        className={`text-[11px] shrink-0 ${
                          ast.status === 'Protected'
                            ? 'text-emerald-400'
                            : ast.status === 'At Risk'
                            ? 'text-rose-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {ast.status}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
      </div>

      {/* Inventory Table + Host Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#0E1117] border border-white/[0.08] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.08] text-sm font-semibold text-white">
            Workload Inventory
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/[0.08] text-[11px] font-medium text-zinc-500">
                  <th className="py-2.5 px-4">Hostname</th>
                  <th className="py-2.5 px-3">IPv4</th>
                  <th className="py-2.5 px-3">Ports</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06] text-xs font-mono">
                {filteredAssets.map((ast) => (
                  <tr
                    key={ast.id}
                    onClick={() => setSelectedAssetId(ast.id)}
                    className={`cursor-pointer transition-colors ${
                      selectedAsset?.id === ast.id ? 'bg-white/[0.05]' : 'hover:bg-white/[0.03]'
                    }`}
                  >
                    <td className="py-2.5 px-4">
                      <div className="text-zinc-100 font-medium">{ast.name}</div>
                      <div className="text-[11px] text-zinc-500 font-sans">{ast.type}</div>
                    </td>
                    <td className="py-2.5 px-3 text-zinc-300 tabular-nums">{ast.ip}</td>
                    <td className="py-2.5 px-3 text-zinc-400 tabular-nums">{ast.openPorts.join(', ')}</td>
                    <td className="py-2.5 px-3 tabular-nums">
                      <span className={ast.riskScore >= 70 ? 'text-rose-400' : 'text-zinc-300'}>
                        {ast.riskScore}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={
                          ast.status === 'Protected'
                            ? 'text-emerald-400'
                            : ast.status === 'At Risk'
                            ? 'text-rose-400'
                            : 'text-amber-400'
                        }
                      >
                        {ast.status}
                      </span>
                    </td>
                    <td
                      className="py-2.5 px-4 text-right whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {ast.status === 'Isolated' ? (
                        <button
                          onClick={() => onIsolateAsset(ast.id, true)}
                          className="h-7 px-2.5 bg-[#090B0F] hover:bg-white/[0.06] text-emerald-400 border border-white/[0.08] rounded text-[11px] font-sans font-medium cursor-pointer"
                        >
                          Restore
                        </button>
                      ) : (
                        <button
                          onClick={() => onIsolateAsset(ast.id, false)}
                          className="h-7 px-2.5 bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-500/30 rounded text-[11px] font-sans font-medium cursor-pointer"
                        >
                          Quarantine
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Asset Inspector */}
        {selectedAsset && (
          <div className="bg-[#0E1117] border border-white/[0.08] rounded-lg p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Server className="w-4 h-4 text-zinc-400" />
                <span>{selectedAsset.name}</span>
              </div>
              <span className="text-xs font-mono text-zinc-500">{selectedAsset.id}</span>
            </div>

            <dl className="space-y-3 text-xs">
              <div>
                <dt className="text-zinc-500">IPv4 &amp; Subnet</dt>
                <dd className="font-mono text-zinc-200 mt-0.5 tabular-nums">
                  {selectedAsset.ip} · {selectedAsset.subnet}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Operating System</dt>
                <dd className="font-mono text-zinc-200 mt-0.5">{selectedAsset.os}</dd>
              </div>
              <div>
                <dt className="text-zinc-500">Listening TCP/UDP Sockets</dt>
                <dd className="font-mono text-zinc-300 mt-0.5 tabular-nums">
                  {selectedAsset.openPorts.map((p) => `:${p}`).join('  ')}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Open CVEs</dt>
                <dd className="font-mono text-rose-400 mt-0.5 tabular-nums">
                  {selectedAsset.vulnerabilitiesCount} vulnerabilities tracked
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Last Telemetry Check-In</dt>
                <dd className="font-mono text-zinc-400 mt-0.5 tabular-nums">{selectedAsset.lastScanTime}</dd>
              </div>
            </dl>

            <div className="pt-3 border-t border-white/[0.08]">
              {selectedAsset.status === 'Isolated' ? (
                <button
                  onClick={() => onIsolateAsset(selectedAsset.id, true)}
                  className="w-full h-9 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium rounded-md cursor-pointer"
                >
                  Restore Network Connectivity
                </button>
              ) : (
                <button
                  onClick={() => onIsolateAsset(selectedAsset.id, false)}
                  className="w-full h-9 bg-rose-600/90 hover:bg-rose-500 text-white text-xs font-medium rounded-md cursor-pointer"
                >
                  Isolate Host via eBPF Policy
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
