import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, TabType } from './components/Sidebar';
import { SOCDashboard } from './components/SOCDashboard';
import { DefenderAI } from './components/DefenderAI';
import { PentestAI } from './components/PentestAI';
import { MitreMatrix } from './components/MitreMatrix';
import { MalwareSandbox } from './components/MalwareSandbox';
import { AssetTopology } from './components/AssetTopology';
import { ComplianceAudit } from './components/ComplianceAudit';
import { SentinelCopilot } from './components/SentinelCopilot';
import { AuditLogModal } from './components/AuditLogModal';
import { IncidentDetailModal } from './components/IncidentDetailModal';

import {
  UserRole,
  IncidentAlert,
  Playbook,
  Asset,
  MitreTechnique,
  ComplianceCheck,
  AuditLogEntry,
  DetectionRule,
  TelemetryEvent,
  Severity,
} from './types';

import {
  INITIAL_ALERTS,
  INITIAL_PLAYBOOKS,
  INITIAL_ASSETS,
  MITRE_TACTICS_DATA,
  INITIAL_COMPLIANCE,
  INITIAL_RULES,
  INITIAL_TELEMETRY,
} from './data/mockCyberData';

const TAB_LABELS: Record<TabType, string> = {
  dashboard: 'Operations / Incident Queue',
  defender: 'Operations / Detection & SOAR',
  pentest: 'Exposure / Attack Surface',
  sandbox: 'Exposure / Artifact Analyzer',
  topology: 'Exposure / Asset Inventory',
  mitre: 'Governance / ATT&CK & Intel',
  compliance: 'Governance / Compliance Audit',
  copilot: 'Governance / Security Copilot',
};

export default function App() {
  const [role, setRole] = useState<UserRole>('SOC Tier 3 Lead');
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');

  const [alerts, setAlerts] = useState<IncidentAlert[]>(INITIAL_ALERTS);
  const [playbooks, setPlaybooks] = useState<Playbook[]>(INITIAL_PLAYBOOKS);
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS);
  const [rules, setRules] = useState<DetectionRule[]>(INITIAL_RULES);
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>(INITIAL_TELEMETRY);
  const [tacticsData, setTacticsData] = useState<MitreTechnique[]>(MITRE_TACTICS_DATA);
  const [complianceChecks, setComplianceChecks] = useState<ComplianceCheck[]>(INITIAL_COMPLIANCE);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditValid, setAuditValid] = useState<boolean>(true);

  const [isAuditModalOpen, setIsAuditModalOpen] = useState<boolean>(false);
  const [selectedAlertForInspection, setSelectedAlertForInspection] = useState<IncidentAlert | null>(null);
  const [quickIntelQuery, setQuickIntelQuery] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const fetchState = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) return;
      const data = await res.json();
      if (data.alerts) setAlerts(data.alerts);
      if (data.playbooks) setPlaybooks(data.playbooks);
      if (data.assets) setAssets(data.assets);
      if (data.rules) setRules(data.rules);
      if (data.telemetry) setTelemetry(data.telemetry);
      if (data.mitreTactics) setTacticsData(data.mitreTactics);
      if (data.compliance) setComplianceChecks(data.compliance);
      if (data.auditLogs) setAuditLogs(data.auditLogs);
      if (data.auditVerification) setAuditValid(data.auditVerification.valid);
    } catch (err) {
      console.error('Failed to load workspace state:', err);
    }
  }, []);

  useEffect(() => {
    fetchState();
    const es = new EventSource('/api/stream');
    es.addEventListener('telemetry', () => {
      fetchState();
    });
    return () => {
      es.close();
    };
  }, [fetchState]);

  const handleExecutePlaybook = async (playbookId: string, alertId?: string) => {
    const res = await fetch(`/api/playbooks/${playbookId}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alertId, role }),
    });
    if (res.ok) {
      await fetchState();
      showToast(alertId ? `Playbook ${playbookId} mitigated ${alertId}` : `Executed ${playbookId}`);
    }
  };

  const handleToggleAutoTrigger = async (playbookId: string, nextVal: boolean) => {
    const res = await fetch(`/api/playbooks/${playbookId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ autoTriggerEnabled: nextVal, role }),
    });
    if (res.ok) {
      await fetchState();
    }
  };

  const handleUpdateAlert = async (
    alertId: string,
    updates: { status?: IncidentAlert['status']; assignee?: string; triageNotes?: string }
  ) => {
    const res = await fetch(`/api/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...updates, role }),
    });
    if (res.ok) {
      await fetchState();
      showToast(`Updated triage state for ${alertId}`);
    }
  };

  const handleIsolateAsset = async (assetId: string, restore = false) => {
    const res = await fetch(`/api/assets/${assetId}/isolate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role, restore }),
    });
    if (res.ok) {
      await fetchState();
      showToast(restore ? `Restored network access for ${assetId}` : `Isolated host ${assetId} via eBPF`);
    }
  };

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    const res = await fetch(`/api/rules/${ruleId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, role }),
    });
    if (res.ok) {
      await fetchState();
    }
  };

  const handleCreateRule = async (payload: {
    title: string;
    format: 'sigma' | 'yara' | 'suricata';
    target: string;
    severity: Severity;
    pattern: string;
    mitreId: string;
  }) => {
    const res = await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, role }),
    });
    if (res.ok) {
      await fetchState();
      showToast(`Deployed rule: ${payload.title}`);
    }
  };

  const handleIngestLog = async (source: string, host: string, raw: string) => {
    const res = await fetch('/api/events/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source, host, raw, role }),
    });
    if (res.ok) {
      const data = await res.json();
      await fetchState();
      if (data.generatedAlert) {
        showToast(`Rule ${data.matchedRule.id} triggered incident ${data.generatedAlert.id}`);
      } else {
        showToast(`Event ${data.event.id} ingested (no rule match)`);
      }
    }
  };

  const handleQuickSearch = (query: string) => {
    setQuickIntelQuery(query);
    setActiveTab('mitre');
  };

  const activeAlertsCount = alerts.filter(
    (a) => a.status === 'Active' || a.status === 'Investigating'
  ).length;

  return (
    <div className="min-h-screen bg-[#090B0F] text-zinc-100 flex flex-col md:flex-row font-sans selection:bg-blue-600 selection:text-white">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeAlertsCount={activeAlertsCount}
        role={role}
        setRole={setRole}
        onOpenAuditLogs={() => setIsAuditModalOpen(true)}
        auditEntriesCount={auditLogs.length}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <Navbar
          activeTabLabel={TAB_LABELS[activeTab]}
          role={role}
          auditValid={auditValid}
          onQuickSearch={handleQuickSearch}
          onOpenCopilot={() => setActiveTab('copilot')}
          onOpenAuditLogs={() => setIsAuditModalOpen(true)}
        />

        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto">
          {activeTab === 'dashboard' && (
            <SOCDashboard
              alerts={alerts}
              playbooks={playbooks}
              assets={assets}
              auditValid={auditValid}
              auditCount={auditLogs.length}
              onSelectAlert={(alert) => setSelectedAlertForInspection(alert)}
              onExecutePlaybook={handleExecutePlaybook}
              onIngestLog={handleIngestLog}
              onNavigateTab={(tab) => setActiveTab(tab)}
            />
          )}

          {activeTab === 'defender' && (
            <DefenderAI
              playbooks={playbooks}
              rules={rules}
              telemetry={telemetry}
              onExecutePlaybook={handleExecutePlaybook}
              onToggleAutoTrigger={handleToggleAutoTrigger}
              onToggleRule={handleToggleRule}
              onCreateRule={handleCreateRule}
              onIngestLog={handleIngestLog}
            />
          )}

          {activeTab === 'pentest' && (
            <PentestAI role={role} onRefreshState={fetchState} />
          )}

          {activeTab === 'sandbox' && (
            <MalwareSandbox role={role} onRefreshState={fetchState} />
          )}

          {activeTab === 'topology' && (
            <AssetTopology assets={assets} onIsolateAsset={handleIsolateAsset} />
          )}

          {activeTab === 'mitre' && (
            <MitreMatrix tacticsData={tacticsData} initialIntelQuery={quickIntelQuery} />
          )}

          {activeTab === 'compliance' && (
            <ComplianceAudit complianceChecks={complianceChecks} />
          )}

          {activeTab === 'copilot' && (
            <SentinelCopilot role={role} onRefreshState={fetchState} />
          )}
        </main>
      </div>

      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-[#0E1117] border border-white/[0.14] text-zinc-100 text-xs font-mono px-4 py-2.5 rounded-md shadow-xl">
          {toastMessage}
        </div>
      )}

      <AuditLogModal
        isOpen={isAuditModalOpen}
        onClose={() => setIsAuditModalOpen(false)}
        logs={auditLogs}
        auditValid={auditValid}
      />

      <IncidentDetailModal
        alert={selectedAlertForInspection}
        onClose={() => setSelectedAlertForInspection(null)}
        onExecutePlaybook={handleExecutePlaybook}
        onUpdateAlert={handleUpdateAlert}
      />
    </div>
  );
}
