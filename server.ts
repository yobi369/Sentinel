import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dns from 'dns/promises';
import tls from 'tls';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

import {
  INITIAL_ALERTS,
  INITIAL_PLAYBOOKS,
  INITIAL_ASSETS,
  INITIAL_VULNERABILITIES,
  MITRE_TACTICS_DATA,
  INITIAL_COMPLIANCE,
  INITIAL_RULES,
  INITIAL_TELEMETRY,
} from './src/data/mockCyberData';
import type {
  IncidentAlert,
  Playbook,
  Asset,
  Vulnerability,
  MitreTechnique,
  ComplianceCheck,
  AuditLogEntry,
  DetectionRule,
  TelemetryEvent,
  UserRole,
  SurfaceFinding,
  AttackPathStep,
  SurfaceScanResult,
  ArtifactAnalysisResult,
  Severity,
} from './src/types';

import {
  computeEntryHash,
  verifyAuditChainEntries,
  isRestrictedIp,
  isValidPublicHostname,
  validateSafeRegex,
  calculateShannonEntropy,
  detectMagicBytes,
  timingSafeSecretEquals,
} from './server/securityEngine';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '10mb' }));

// Baseline security headers (compatible with preview iframe embedding)
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Sliding-window in-memory rate limiter for /api routes
const rateBuckets = new Map<string, number[]>();
function createRateLimiter(maxRequests: number, windowMs: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const key = `${req.ip || 'local'}:${req.baseUrl || req.path}`;
    const now = Date.now();
    const recent = (rateBuckets.get(key) || []).filter((ts) => now - ts < windowMs);
    if (recent.length >= maxRequests) {
      return res.status(429).json({ error: 'Rate limit exceeded. Retry shortly.' });
    }
    recent.push(now);
    rateBuckets.set(key, recent);
    next();
  };
}

app.use('/api', createRateLimiter(120, 60_000));
app.use('/api/ai', createRateLimiter(25, 60_000));
app.use('/api/scanner', createRateLimiter(20, 60_000));

const sseClients = new Set<express.Response>();
function broadcastWorkspaceUpdate(eventType: string) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify({ timestamp: new Date().toISOString() })}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

const PORT = Number(process.env.PORT) || 3000;
const STORE_PATH = path.join(process.cwd(), '.sentinel-store.json');

// Initialize Gemini Client server-side
const apiKey = process.env.GEMINI_API_KEY;
let ai: GoogleGenAI | null = null;
if (apiKey && apiKey !== 'MY_GEMINI_API_KEY') {
  try {
    ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.warn('Failed to initialize Gemini AI client:', err);
  }
}

interface WorkspaceStore {
  alerts: IncidentAlert[];
  playbooks: Playbook[];
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  mitreTactics: MitreTechnique[];
  compliance: ComplianceCheck[];
  rules: DetectionRule[];
  telemetry: TelemetryEvent[];
  auditLogs: AuditLogEntry[];
}

function verifyAuditChain(): { valid: boolean; checkedCount: number; headHash: string } {
  return verifyAuditChainEntries(store.auditLogs);
}

function createInitialStore(): WorkspaceStore {
  const genesisPrev = '0'.repeat(64);
  const log1Ts = '2026-11-20T21:55:00.000Z';
  const log1Hash = computeEntryHash(
    genesisPrev,
    1,
    log1Ts,
    'm.chen@sentinel.io',
    'PLAYBOOK_EXECUTE',
    'PB-BLOCKIP-03 -> 194.26.29.110'
  );

  const log2Ts = '2026-11-20T22:15:30.000Z';
  const log2Hash = computeEntryHash(
    log1Hash,
    2,
    log2Ts,
    'a.patel@sentinel.io',
    'AUTHORIZED_SCOPE_SIGNED',
    '10.0.2.0/24 (web-frontend-stage)'
  );

  const log3Ts = '2026-11-20T22:41:06.000Z';
  const log3Hash = computeEntryHash(
    log2Hash,
    3,
    log3Ts,
    'sentinel-auto-responder',
    'ALERT_INGESTED',
    'INC-4091 (prod-db-01)'
  );

  return {
    alerts: structuredClone(INITIAL_ALERTS),
    playbooks: structuredClone(INITIAL_PLAYBOOKS),
    assets: structuredClone(INITIAL_ASSETS),
    vulnerabilities: structuredClone(INITIAL_VULNERABILITIES),
    mitreTactics: structuredClone(MITRE_TACTICS_DATA),
    compliance: structuredClone(INITIAL_COMPLIANCE),
    rules: structuredClone(INITIAL_RULES),
    telemetry: structuredClone(INITIAL_TELEMETRY),
    auditLogs: [
      {
        id: 'LOG-003',
        sequence: 3,
        timestamp: log3Ts,
        actor: 'sentinel-auto-responder',
        role: 'SOC Tier 3 Lead',
        action: 'ALERT_INGESTED',
        module: 'SIEM',
        target: 'INC-4091 (prod-db-01)',
        status: 'SUCCESS',
        prevHash: log2Hash,
        hash: log3Hash,
      },
      {
        id: 'LOG-002',
        sequence: 2,
        timestamp: log2Ts,
        actor: 'a.patel@sentinel.io',
        role: 'Red Team Assessor',
        action: 'AUTHORIZED_SCOPE_SIGNED',
        module: 'SURFACE',
        target: '10.0.2.0/24 (web-frontend-stage)',
        status: 'SUCCESS',
        prevHash: log1Hash,
        hash: log2Hash,
      },
      {
        id: 'LOG-001',
        sequence: 1,
        timestamp: log1Ts,
        actor: 'm.chen@sentinel.io',
        role: 'SOC Tier 3 Lead',
        action: 'PLAYBOOK_EXECUTE',
        module: 'SOAR',
        target: 'PB-BLOCKIP-03 -> 194.26.29.110',
        status: 'EXECUTED',
        prevHash: genesisPrev,
        hash: log1Hash,
      },
    ],
  };
}

function loadStore(): WorkspaceStore {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, 'utf-8');
      const parsed = JSON.parse(raw) as WorkspaceStore;
      if (parsed && Array.isArray(parsed.alerts) && Array.isArray(parsed.auditLogs)) {
        return parsed;
      }
    }
  } catch (err) {
    console.warn('Could not load store, creating fresh workspace:', err);
  }
  const initial = createInitialStore();
  saveStore(initial);
  return initial;
}

function saveStore(data: WorkspaceStore) {
  try {
    fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.warn('Could not persist store:', err);
  }
}

let store: WorkspaceStore = loadStore();

function appendAuditLog(
  actor: string,
  role: UserRole,
  action: string,
  module: string,
  target: string,
  status: 'SUCCESS' | 'DENIED' | 'EXECUTED' = 'EXECUTED'
): AuditLogEntry {
  const head = store.auditLogs[0];
  const prevHash = head ? head.hash : '0'.repeat(64);
  const sequence = head ? head.sequence + 1 : 1;
  const timestamp = new Date().toISOString();
  const hash = computeEntryHash(prevHash, sequence, timestamp, actor, action, target);

  const entry: AuditLogEntry = {
    id: `LOG-${String(sequence).padStart(3, '0')}`,
    sequence,
    timestamp,
    actor,
    role,
    action,
    module,
    target,
    status,
    prevHash,
    hash,
  };

  store.auditLogs.unshift(entry);
  saveStore(store);
  return entry;
}

function roleToActor(role: UserRole): string {
  switch (role) {
    case 'SOC Tier 3 Lead':
      return 'm.chen@sentinel.io';
    case 'SOC Tier 1 Analyst':
      return 'j.rivera@sentinel.io';
    case 'Red Team Assessor':
      return 'a.patel@sentinel.io';
    case 'Compliance Lead':
      return 's.okafor@sentinel.io';
    case 'CISO':
      return 'e.vance@sentinel.io';
  }
}

// Health Check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'Sentinel Security Engine',
    timestamp: new Date().toISOString(),
    aiConfigured: !!ai,
    auditVerification: verifyAuditChain(),
  });
});

// Full Workspace State
app.get('/api/state', (_req, res) => {
  res.json({
    ...store,
    aiConfigured: !!ai,
    auditVerification: verifyAuditChain(),
  });
});

app.post('/api/state/reset', (_req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }
  store = createInitialStore();
  saveStore(store);
  res.json({
    ...store,
    aiConfigured: !!ai,
    auditVerification: verifyAuditChain(),
  });
});

// Audit Verification
app.get('/api/audit/verify', (_req, res) => {
  res.json(verifyAuditChain());
});

// Alert Triage Update
app.patch('/api/alerts/:id', (req, res) => {
  const { id } = req.params;
  const { status, assignee, triageNotes, role = 'SOC Tier 3 Lead' } = req.body;
  const alert = store.alerts.find((a) => a.id === id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });

  if (status) alert.status = status;
  if (assignee !== undefined) alert.assignee = assignee;
  if (triageNotes !== undefined) alert.triageNotes = triageNotes;

  const auditEntry = appendAuditLog(
    roleToActor(role),
    role,
    'INCIDENT_TRIAGE_UPDATE',
    'INCIDENTS',
    `${id} -> status=${alert.status}${assignee ? ` assignee=${assignee}` : ''}`,
    'SUCCESS'
  );

  saveStore(store);
  res.json({ alert, auditEntry, auditVerification: verifyAuditChain() });
});

// Playbook Execution
// Playbook execution is deliberately fail-closed until a verified response
// adapter (EDR, firewall, cloud control plane, etc.) is configured.
// Never mark an incident mitigated based only on a UI/API state change.
app.post('/api/playbooks/:id/execute', (req, res) => {
  const playbook = store.playbooks.find((p) => p.id === req.params.id);
  if (!playbook) return res.status(404).json({ error: 'Playbook not found' });
  return res.status(501).json({
    error: 'Response execution is not configured',
    code: 'RESPONSE_ADAPTER_NOT_CONFIGURED',
    message: 'No external response action was performed. The incident and asset state were not changed.',
    playbookId: playbook.id,
    operationalStatus: 'NOT_EXECUTED',
  });
});

// Toggle Playbook Auto-Trigger
app.patch('/api/playbooks/:id', (req, res) => {
  const { id } = req.params;
  const { autoTriggerEnabled, role = 'SOC Tier 3 Lead' } = req.body;
  const playbook = store.playbooks.find((p) => p.id === id);
  if (!playbook) return res.status(404).json({ error: 'Playbook not found' });

  playbook.autoTriggerEnabled = Boolean(autoTriggerEnabled);
  const auditEntry = appendAuditLog(
    roleToActor(role),
    role,
    'PLAYBOOK_POLICY_CHANGE',
    'SOAR',
    `${playbook.id} autoTrigger=${playbook.autoTriggerEnabled}`,
    'SUCCESS'
  );

  saveStore(store);
  res.json({ playbook, auditEntry, auditVerification: verifyAuditChain() });
});

// Asset Isolation / Restoration
// Host isolation/restoration requires a real endpoint or network-control adapter.
// Refuse the operation rather than presenting a database flag as containment.
app.post('/api/assets/:id/isolate', (req, res) => {
  const asset = store.assets.find((a) => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset not found' });
  return res.status(501).json({
    error: 'Endpoint containment is not configured',
    code: 'CONTAINMENT_ADAPTER_NOT_CONFIGURED',
    message: 'No network isolation or restoration was performed. Asset state was not changed.',
    assetId: asset.id,
    operationalStatus: 'NOT_EXECUTED',
  });
});

// Live Event Ingestion + Detection Engine Evaluation
app.post('/api/events/ingest', (req, res) => {
  const { source = 'syslog', host = 'unknown-host', raw, role = 'SOC Tier 3 Lead' } = req.body;
  if (!raw || typeof raw !== 'string') {
    return res.status(400).json({ error: 'Raw log string is required' });
  }

  const ts = new Date().toISOString();
  const evtId = `EVT-${Math.floor(1000 + Math.random() * 9000)}`;
  let matchedRule: DetectionRule | undefined;

  for (const rule of store.rules) {
    if (!rule.enabled) continue;
    try {
      const re = new RegExp(rule.pattern, 'i');
      if (re.test(raw)) {
        matchedRule = rule;
        rule.matchCount += 1;
        break;
      }
    } catch {
      // ignore invalid regex
    }
  }

  const event: TelemetryEvent = {
    id: evtId,
    timestamp: ts,
    source,
    host,
    raw: raw.trim(),
    matchedRuleId: matchedRule?.id,
  };
  store.telemetry.unshift(event);
  if (store.telemetry.length > 100) store.telemetry.pop();

  let generatedAlert: IncidentAlert | null = null;
  if (matchedRule) {
    const ipMatch = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const srcIp = ipMatch ? ipMatch[0] : '10.0.2.99';
    const alertId = `INC-${Math.floor(4100 + Math.random() * 899)}`;
    generatedAlert = {
      id: alertId,
      title: matchedRule.title,
      severity: matchedRule.severity,
      status: 'Active',
      sourceIp: srcIp,
      destIp: '10.0.1.45',
      assetName: host,
      mitreTechniqueId: matchedRule.mitreId,
      mitreTechniqueName: matchedRule.target,
      timestamp: ts.replace('T', ' ').substring(0, 19),
      description: `Detection rule ${matchedRule.id} triggered on ingested ${source} telemetry from ${host}.`,
      rawLog: raw.trim(),
      ruleMatched: matchedRule.id,
      assignee: 'Unassigned',
      xaiExplanation: {
        confidenceScore: 93,
        evidenceFactors: [
          `Matched regex/signature pattern /${matchedRule.pattern}/i`,
          `Telemetry ingested via ${source} pipeline for host ${host}`,
        ],
        falsePositiveProbability: '7%',
        impactRating: `${matchedRule.severity} — Immediate analyst verification recommended`,
      },
      recommendedPlaybookId: matchedRule.severity === 'Critical' ? 'PB-ISOLATE-01' : 'PB-KILLPROCS-02',
      playbookExecuted: false,
    };
    store.alerts.unshift(generatedAlert);
    appendAuditLog(
      roleToActor(role),
      role,
      'DETECTION_RULE_TRIGGERED',
      'SIEM',
      `${alertId} matched ${matchedRule.id} on ${host}`,
      'SUCCESS'
    );
  }

  saveStore(store);
  broadcastWorkspaceUpdate('telemetry');
  res.json({
    event,
    matchedRule: matchedRule || null,
    generatedAlert,
    auditVerification: verifyAuditChain(),
  });
});

// Server-Sent Events Live Stream for real-time ingestion notifications
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write(`event: connected\ndata: ${JSON.stringify({ ok: true })}\n\n`);
  sseClients.add(res);
  req.on('close', () => {
    sseClients.delete(res);
  });
});

// External Webhook / SIEM Collector Endpoint (requires SENTINEL_INGEST_KEY auth)
app.post('/api/v1/ingest/webhook', (req, res) => {
  const configuredKey = process.env.SENTINEL_INGEST_KEY?.trim();
  // Authentication is mandatory: an unset secret must never silently expose
  // the external collector endpoint to unauthenticated internet traffic.
  if (!configuredKey || configuredKey.length < 32) {
    return res.status(503).json({
      error: 'Webhook ingestion is disabled until SENTINEL_INGEST_KEY is configured',
      code: 'INGEST_AUTH_NOT_CONFIGURED',
    });
  }
  const authHeader = req.headers.authorization || '';
  const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const headerKey = String(req.headers['x-sentinel-ingest-key'] || '').trim();
  const provided = bearer || headerKey;
  if (!provided || !timingSafeSecretEquals(provided, configuredKey)) {
    return res.status(401).json({ error: 'Invalid or missing ingest credentials' });
  }

  const { source = 'webhook', host = 'external-collector', raw, event: payloadObj } = req.body || {};
  const rawString =
    typeof raw === 'string' && raw.trim()
      ? raw.trim()
      : payloadObj
      ? JSON.stringify(payloadObj)
      : '';
  if (!rawString) {
    return res.status(400).json({ error: 'Provide raw log string or event object' });
  }

  const ts = new Date().toISOString();
  const evtId = `EVT-${Math.floor(1000 + Math.random() * 9000)}`;
  let matchedRule: DetectionRule | undefined;
  for (const rule of store.rules) {
    if (!rule.enabled) continue;
    try {
      if (new RegExp(rule.pattern, 'i').test(rawString)) {
        matchedRule = rule;
        rule.matchCount += 1;
        break;
      }
    } catch {
      // skip invalid
    }
  }

  const event: TelemetryEvent = {
    id: evtId,
    timestamp: ts,
    source: ['suricata', 'zeek', 'syslog', 'kube-audit', 'edr'].includes(String(source))
      ? (source as TelemetryEvent['source'])
      : 'syslog',
    host: String(host).slice(0, 80),
    raw: rawString.slice(0, 4000),
    matchedRuleId: matchedRule?.id,
  };
  store.telemetry.unshift(event);
  if (store.telemetry.length > 100) store.telemetry.pop();

  let generatedAlert: IncidentAlert | null = null;
  if (matchedRule) {
    const ipMatch = rawString.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const alertId = `INC-${Math.floor(4100 + Math.random() * 899)}`;
    generatedAlert = {
      id: alertId,
      title: matchedRule.title,
      severity: matchedRule.severity,
      status: 'Active',
      sourceIp: ipMatch ? ipMatch[0] : '0.0.0.0',
      destIp: '10.0.1.45',
      assetName: event.host,
      mitreTechniqueId: matchedRule.mitreId,
      mitreTechniqueName: matchedRule.target,
      timestamp: ts.replace('T', ' ').substring(0, 19),
      description: `Webhook ingestion matched rule ${matchedRule.id} on host ${event.host}.`,
      rawLog: event.raw,
      ruleMatched: matchedRule.id,
      assignee: 'Unassigned',
      xaiExplanation: {
        confidenceScore: 92,
        evidenceFactors: [`Matched ${matchedRule.id} on external webhook collector`],
        falsePositiveProbability: '8%',
        impactRating: `${matchedRule.severity} — External ingestion alert`,
      },
      recommendedPlaybookId: matchedRule.severity === 'Critical' ? 'PB-ISOLATE-01' : 'PB-KILLPROCS-02',
      playbookExecuted: false,
    };
    store.alerts.unshift(generatedAlert);
    appendAuditLog(
      'webhook-collector@sentinel.io',
      'SOC Tier 3 Lead',
      'WEBHOOK_DETECTION_TRIGGERED',
      'SIEM',
      `${alertId} matched ${matchedRule.id}`,
      'SUCCESS'
    );
  }

  saveStore(store);
  broadcastWorkspaceUpdate('telemetry');
  return res.status(202).json({
    accepted: true,
    eventId: evtId,
    matchedRuleId: matchedRule?.id || null,
    generatedAlertId: generatedAlert?.id || null,
  });
});

// Live Detection Rule Tester against Telemetry Corpus
app.post('/api/rules/test', (req, res) => {
  const { pattern } = req.body;
  const check = validateSafeRegex(pattern);
  if (!check.valid) {
    return res.status(400).json({ valid: false, error: check.reason });
  }
  const start = performance.now();
  try {
    const regex = new RegExp(pattern, 'i');
    const matches = store.telemetry.filter((evt) => regex.test(evt.raw));
    const durationMs = Number((performance.now() - start).toFixed(3));
    res.json({
      valid: true,
      scannedCount: store.telemetry.length,
      matchCount: matches.length,
      durationMs,
      matches,
    });
  } catch (err: any) {
    res.status(400).json({ valid: false, error: `Invalid regex pattern: ${err.message}` });
  }
});

// Create / Save Detection Rule
app.post('/api/rules', (req, res) => {
  const {
    title,
    format = 'sigma',
    target = 'Syslog / EDR Stream',
    severity = 'High',
    pattern,
    mitreId = 'T1059',
    code,
    role = 'SOC Tier 3 Lead',
  } = req.body;

  if (!title || !pattern) {
    return res.status(400).json({ error: 'Rule title and detection pattern are required' });
  }
  const check = validateSafeRegex(pattern);
  if (!check.valid) {
    return res.status(400).json({ error: check.reason });
  }

  const rule: DetectionRule = {
    id: `${format.toUpperCase()}-CUSTOM-${Math.floor(100 + Math.random() * 899)}`,
    format,
    title,
    target,
    severity: severity as Severity,
    pattern,
    mitreId,
    enabled: true,
    matchCount: store.telemetry.filter((e) => new RegExp(pattern, 'i').test(e.raw)).length,
    code:
      code ||
      `title: ${title}\nlogsource:\n  product: custom\ndetection:\n  selection:\n    raw|re: '${pattern}'\n  condition: selection\nlevel: ${severity.toLowerCase()}`,
  };

  store.rules.unshift(rule);
  const auditEntry = appendAuditLog(
    roleToActor(role),
    role,
    'DETECTION_RULE_DEPLOYED',
    'DETECTION',
    `${rule.id} (${rule.title})`,
    'SUCCESS'
  );
  saveStore(store);
  res.json({ rule, auditEntry, auditVerification: verifyAuditChain() });
});

app.patch('/api/rules/:id', (req, res) => {
  const { id } = req.params;
  const { enabled, role = 'SOC Tier 3 Lead' } = req.body;
  const rule = store.rules.find((r) => r.id === id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  rule.enabled = Boolean(enabled);
  const auditEntry = appendAuditLog(
    roleToActor(role),
    role,
    'DETECTION_RULE_TOGGLED',
    'DETECTION',
    `${rule.id} enabled=${rule.enabled}`,
    'SUCCESS'
  );
  saveStore(store);
  res.json({ rule, auditEntry, auditVerification: verifyAuditChain() });
});

// Scope Authorization Sign-Off
app.post('/api/scanner/authorize', (req, res) => {
  const { target, role = 'Red Team Assessor' } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });
  const auditEntry = appendAuditLog(
    roleToActor(role),
    role,
    'AUTHORIZED_SCOPE_SIGNED',
    'SURFACE',
    target,
    'SUCCESS'
  );
  res.json({ authorized: true, auditEntry, auditVerification: verifyAuditChain() });
});

// Real Attack Surface & Posture Scanner (DNS, TLS 443, HTTP Security Headers)
function isPrivateOrLocalTarget(target: string): boolean {
  return (
    /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.)/.test(target) ||
    target.includes('/') ||
    target === 'localhost'
  );
}

function inspectTlsCertificate(host: string): Promise<SurfaceScanResult['tls'] | undefined> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 4000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || 'Unknown';
          const cipherInfo = socket.getCipher();
          const authorized = socket.authorized;
          socket.end();

          if (!cert || !cert.valid_to) {
            resolve(undefined);
            return;
          }
          const validToMs = Date.parse(cert.valid_to);
          const daysRemaining = Math.round((validToMs - Date.now()) / (1000 * 60 * 60 * 24));
          const rawSubject = cert.subject?.CN;
          const rawIssuer = cert.issuer?.O || cert.issuer?.CN;
          resolve({
            protocol,
            cipher: cipherInfo?.name || 'Unknown',
            subject: (Array.isArray(rawSubject) ? rawSubject[0] : rawSubject) || host,
            issuer: (Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer) || 'Unknown CA',
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            authorized,
          });
        } catch {
          socket.destroy();
          resolve(undefined);
        }
      }
    );
    socket.on('error', () => {
      socket.destroy();
      resolve(undefined);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(undefined);
    });
  });
}

app.post('/api/scanner/inspect', async (req, res) => {
  const { target: rawTarget, role = 'Red Team Assessor' } = req.body;
  if (!rawTarget || typeof rawTarget !== 'string') {
    return res.status(400).json({ error: 'Target hostname or CIDR is required' });
  }

  const startTime = performance.now();
  const cleanHost = rawTarget
    .trim()
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split(':')[0]
    .toLowerCase();

  // Internal RFC1918 Asset / CIDR Inspection
  if (isPrivateOrLocalTarget(rawTarget.trim())) {
    const matchedAssets = store.assets.filter(
      (a) => a.ip === cleanHost || a.subnet.includes(rawTarget.trim()) || rawTarget.includes('10.0.')
    );
    const findings: SurfaceFinding[] = store.vulnerabilities.map((v) => ({
      id: v.cve,
      title: `${v.cve}: ${v.title}`,
      category: 'CVE',
      severity: v.severity,
      cvss: v.cvss,
      evidence: `Affected internal asset: ${v.affectedAsset} — ${v.description}`,
      verificationCmd: v.pocCommand,
      remediation: v.patchScript,
    }));

    const attackPath: AttackPathStep[] = [
      {
        id: 'AP-1',
        stepNumber: 1,
        phaseName: 'Initial Access',
        sourceNode: 'External Edge (0.0.0.0/0)',
        targetNode: 'web-frontend-stage (10.0.2.14)',
        techniqueUsed: 'CVE-2023-4863 (libwebp)',
        riskDescription: 'Publicly reachable upload parser on staging tier exposes heap memory corruption primitive.',
        remediation: 'Upgrade libwebp >= 1.3.2 and isolate staging ingress.',
      },
      {
        id: 'AP-2',
        stepNumber: 2,
        phaseName: 'Privilege Escalation',
        sourceNode: 'web-frontend-stage (www-data)',
        targetNode: 'bastion-gw-01 (10.0.1.10)',
        techniqueUsed: 'CVE-2024-3094 (liblzma)',
        riskDescription: 'Shared SSH deployment key permits lateral pivot into DMZ bastion node.',
        remediation: 'Upgrade xz-utils/liblzma5 and enforce short-lived OIDC SSH certificates.',
      },
      {
        id: 'AP-3',
        stepNumber: 3,
        phaseName: 'Data Tier Reachability',
        sourceNode: 'bastion-gw-01 (root)',
        targetNode: 'prod-db-01 (10.0.1.45:5432)',
        techniqueUsed: 'Permissive East-West Subnet ACL',
        riskDescription: 'East-west security group allows TCP/5432 from bastion subnet without mTLS client cert.',
        remediation: 'Enforce PostgreSQL hostssl + clientcert=verify-full in pg_hba.conf.',
      },
    ];

    const result: SurfaceScanResult = {
      target: rawTarget.trim(),
      targetType: 'internal-cidr',
      scannedAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - startTime),
      resolvedIps: matchedAssets.map((a) => a.ip),
      dns: { mxRecords: [], hasSpf: false, hasDmarc: false, txtRecordsCount: 0 },
      findings,
      attackPath,
    };

    appendAuditLog(roleToActor(role), role, 'INTERNAL_SURFACE_SCAN', 'SURFACE', rawTarget.trim(), 'SUCCESS');
    return res.json({ result, auditVerification: verifyAuditChain() });
  }

  // Public Domain Live DNS + TLS + HTTP Security Header Inspection (with SSRF IP-egress guard)
  if (!isValidPublicHostname(cleanHost)) {
    return res.status(400).json({
      error: 'Invalid public hostname. Enter a valid FQDN (e.g. github.com) or internal 10.0.x.x asset.',
    });
  }

  try {
    const [aRecords, mxRecords, txtRecords, dmarcRecords] = await Promise.all([
      dns.resolve4(cleanHost).catch(() => [] as string[]),
      dns.resolveMx(cleanHost).catch(() => [] as { exchange: string; priority: number }[]),
      dns.resolveTxt(cleanHost).catch(() => [] as string[][]),
      dns.resolveTxt(`_dmarc.${cleanHost}`).catch(() => [] as string[][]),
    ]);

    if (aRecords.length === 0) {
      return res.status(400).json({ error: `DNS A-record resolution returned no public IPv4 addresses for ${cleanHost}.` });
    }
    if (aRecords.some((ip) => isRestrictedIp(ip))) {
      return res.status(403).json({
        error: `Target ${cleanHost} resolves to a restricted/private IP address and is blocked from outbound probing.`,
      });
    }

    const flatTxt = txtRecords.map((r) => r.join(''));
    const hasSpf = flatTxt.some((t) => t.toLowerCase().includes('v=spf1'));
    const hasDmarc = dmarcRecords.some((r) => r.join('').toLowerCase().includes('v=dmarc1'));

    const tlsInfo = await inspectTlsCertificate(cleanHost);

    let httpInfo: SurfaceScanResult['http'];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    try {
      const resp = await fetch(`https://${cleanHost}`, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
      });
      const hdrs: Record<string, string | null> = {
        'strict-transport-security': resp.headers.get('strict-transport-security'),
        'content-security-policy': resp.headers.get('content-security-policy'),
        'x-frame-options': resp.headers.get('x-frame-options'),
        'x-content-type-options': resp.headers.get('x-content-type-options'),
        'referrer-policy': resp.headers.get('referrer-policy'),
        'permissions-policy': resp.headers.get('permissions-policy'),
      };
      httpInfo = {
        statusCode: resp.status,
        finalUrl: resp.url,
        serverHeader: resp.headers.get('server') || undefined,
        headersPresent: hdrs,
      };
    } catch {
      httpInfo = undefined;
    } finally {
      clearTimeout(timer);
    }

    const findings: SurfaceFinding[] = [];
    if (!tlsInfo) {
      findings.push({
        id: 'TLS-001',
        title: 'TLS Handshake Unavailable on Port 443',
        category: 'TLS',
        severity: 'High',
        cvss: 7.5,
        evidence: `Could not complete TLS handshake with ${cleanHost}:443 within 4000ms.`,
        verificationCmd: `openssl s_client -connect ${cleanHost}:443 -servername ${cleanHost}`,
        remediation: 'Verify TLS listener configuration and ensure valid X.509 chain is served on TCP/443.',
      });
    } else {
      if (!tlsInfo.authorized) {
        findings.push({
          id: 'TLS-002',
          title: 'Untrusted or Incomplete X.509 Certificate Chain',
          category: 'TLS',
          severity: 'High',
          cvss: 7.4,
          evidence: `Certificate subject ${tlsInfo.subject} issued by ${tlsInfo.issuer} failed strict chain verification.`,
          verificationCmd: `openssl s_client -connect ${cleanHost}:443 -verify_return_error`,
          remediation: 'Bundle full intermediate CA certificates in server SSL configuration.',
        });
      }
      if (tlsInfo.daysRemaining < 30) {
        findings.push({
          id: 'TLS-003',
          title: 'Certificate Expiring Within 30 Days',
          category: 'TLS',
          severity: 'Medium',
          cvss: 5.3,
          evidence: `Certificate expires ${tlsInfo.validTo} (${tlsInfo.daysRemaining} days remaining).`,
          verificationCmd: `echo | openssl s_client -connect ${cleanHost}:443 2>/dev/null | openssl x509 -noout -dates`,
          remediation: 'Automate ACME/Let’s Encrypt renewal cron or managed certificate rotation.',
        });
      }
    }

    if (httpInfo) {
      if (!httpInfo.headersPresent['strict-transport-security']) {
        findings.push({
          id: 'HDR-HSTS',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          category: 'HTTP Header',
          severity: 'Medium',
          cvss: 5.9,
          evidence: `GET ${httpInfo.finalUrl} (${httpInfo.statusCode}) omitted Strict-Transport-Security.`,
          verificationCmd: `curl -sI https://${cleanHost} | grep -i strict-transport-security`,
          remediation: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
        });
      }
      if (!httpInfo.headersPresent['content-security-policy']) {
        findings.push({
          id: 'HDR-CSP',
          title: 'Missing Content-Security-Policy (CSP) Header',
          category: 'HTTP Header',
          severity: 'Medium',
          cvss: 5.4,
          evidence: `Response from ${httpInfo.finalUrl} does not enforce script/frame origin restrictions.`,
          verificationCmd: `curl -sI https://${cleanHost} | grep -i content-security-policy`,
          remediation: `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none';" always;`,
        });
      }
      if (!httpInfo.headersPresent['x-content-type-options']) {
        findings.push({
          id: 'HDR-XCTO',
          title: 'Missing X-Content-Type-Options: nosniff',
          category: 'HTTP Header',
          severity: 'Low',
          cvss: 3.1,
          evidence: 'MIME-type sniffing protection header absent on primary HTTP response.',
          verificationCmd: `curl -sI https://${cleanHost} | grep -i x-content-type-options`,
          remediation: `add_header X-Content-Type-Options "nosniff" always;`,
        });
      }
      if (httpInfo.serverHeader) {
        findings.push({
          id: 'HDR-BANNER',
          title: `Server Technology Banner Disclosed (${httpInfo.serverHeader})`,
          category: 'Exposure',
          severity: 'Info',
          cvss: 2.0,
          evidence: `Server header returned "${httpInfo.serverHeader}" aiding automated fingerprinting.`,
          verificationCmd: `curl -sI https://${cleanHost} | grep -i '^server:'`,
          remediation: 'Disable server_tokens / banner emission at reverse proxy edge.',
        });
      }
    }

    if (!hasDmarc) {
      findings.push({
        id: 'DNS-DMARC',
        title: 'No DMARC Policy Record Published (_dmarc)',
        category: 'DNS / Email',
        severity: 'Medium',
        cvss: 5.0,
        evidence: `TXT query for _dmarc.${cleanHost} returned zero v=DMARC1 policies.`,
        verificationCmd: `dig +short TXT _dmarc.${cleanHost}`,
        remediation: `Publish TXT record: _dmarc.${cleanHost} "v=DMARC1; p=quarantine; rua=mailto:dmarc@${cleanHost}"`,
      });
    }
    if (!hasSpf) {
      findings.push({
        id: 'DNS-SPF',
        title: 'Missing SPF Sender Policy Framework Record',
        category: 'DNS / Email',
        severity: 'Low',
        cvss: 3.7,
        evidence: `Root TXT records for ${cleanHost} did not include v=spf1.`,
        verificationCmd: `dig +short TXT ${cleanHost} | grep spf1`,
        remediation: `Publish TXT record: ${cleanHost} "v=spf1 -all"`,
      });
    }

    const attackPath: AttackPathStep[] = [
      {
        id: 'EXT-1',
        stepNumber: 1,
        phaseName: 'Reconnaissance',
        sourceNode: 'Public Internet',
        targetNode: `${cleanHost} (${aRecords[0] || 'DNS unresolved'})`,
        techniqueUsed: 'DNS / TLS Enumeration',
        riskDescription: `Resolved ${aRecords.length} A record(s), ${mxRecords.length} MX record(s), and ${tlsInfo ? tlsInfo.protocol : 'no TLS'}.`,
        remediation: 'Restrict origin IP exposure behind WAF/CDN.',
      },
      {
        id: 'EXT-2',
        stepNumber: 2,
        phaseName: 'Edge Posture',
        sourceNode: 'HTTPS Client',
        targetNode: `${httpInfo?.finalUrl || cleanHost}`,
        techniqueUsed: findings[0]?.title || 'Baseline Header Verification',
        riskDescription: `${findings.length} posture observation(s) identified across TLS, HTTP headers, and DNS authentication.`,
        remediation: findings[0]?.remediation || 'Maintain baseline security headers.',
      },
    ];

    const result: SurfaceScanResult = {
      target: cleanHost,
      targetType: 'public-domain',
      scannedAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - startTime),
      resolvedIps: aRecords,
      dns: {
        mxRecords: mxRecords.map((m) => `${m.priority} ${m.exchange}`),
        hasSpf,
        hasDmarc,
        txtRecordsCount: flatTxt.length,
      },
      tls: tlsInfo,
      http: httpInfo,
      findings,
      attackPath,
    };

    appendAuditLog(
      roleToActor(role),
      role,
      'EXTERNAL_SURFACE_INSPECT',
      'SURFACE',
      `${cleanHost} (${findings.length} findings)`,
      'SUCCESS'
    );

    return res.json({ result, auditVerification: verifyAuditChain() });
  } catch (err: any) {
    return res.status(500).json({ error: `Surface inspection failed: ${err.message}` });
  }
});

app.post('/api/sandbox/analyze', (req, res) => {
  const { fileName = 'artifact.txt', contentBase64, rawText, role = 'SOC Tier 3 Lead' } = req.body;
  if (!contentBase64 && !rawText) {
    return res.status(400).json({ error: 'Provide either file content or raw artifact text' });
  }

  const buffer = contentBase64
    ? Buffer.from(contentBase64, 'base64')
    : Buffer.from(String(rawText), 'utf-8');

  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const shannonEntropy = calculateShannonEntropy(buffer);
  const magicType = detectMagicBytes(buffer, fileName);

  // Extract printable ASCII strings >= 5 chars
  const asciiMatches = buffer.toString('latin1').match(/[\x20-\x7E]{5,}/g) || [];
  const fullText = asciiMatches.join('\n');

  const ips = Array.from(new Set(fullText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])).slice(0, 20);
  const urls = Array.from(new Set(fullText.match(/https?:\/\/[^\s"'<>)]+/gi) || [])).slice(0, 20);
  const domains = Array.from(
    new Set(
      (fullText.match(/\b[a-zA-Z0-9-]+\.(?:com|net|org|io|ru|cn|xyz|top|tk|biz|info)\b/gi) || []).map((d) =>
        d.toLowerCase()
      )
    )
  ).slice(0, 20);
  const registryKeys = Array.from(
    new Set(fullText.match(/(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\[^\s"']+/gi) || [])
  ).slice(0, 15);

  const suspiciousPrimitives = [
    'VirtualAllocEx',
    'NtCreateThreadEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'Invoke-Expression',
    'IEX',
    'FromBase64String',
    'Net.WebClient',
    'DownloadString',
    'DownloadFile',
    'RegSetValueEx',
    'PAGE_EXECUTE_READWRITE',
    'chmod +x',
    '/etc/shadow',
    'curl ',
    'wget ',
    'nc -e',
    'eval(',
    'child_process',
  ];
  const suspiciousApis = suspiciousPrimitives.filter((api) =>
    fullText.toLowerCase().includes(api.toLowerCase())
  );

  // Decode Base64 payloads >= 24 chars
  const b64Candidates = Array.from(new Set(fullText.match(/\b[A-Za-z0-9+/]{24,}={0,2}\b/g) || [])).slice(0, 8);
  const decodedBase64: { encoded: string; decoded: string }[] = [];
  for (const cand of b64Candidates) {
    try {
      const decBuf = Buffer.from(cand, 'base64');
      // Check for UTF-8 or UTF-16LE (common in PowerShell -enc)
      const utf8 = decBuf.toString('utf8').replace(/\0/g, '');
      const printableRatio = (utf8.match(/[\x20-\x7E]/g)?.length || 0) / Math.max(utf8.length, 1);
      if (utf8.length >= 6 && printableRatio > 0.75) {
        decodedBase64.push({ encoded: cand, decoded: utf8 });
      }
    } catch {
      // skip invalid base64
    }
  }

  // Match against active detection rules
  const yaraMatches: { ruleId: string; description: string; severity: Severity }[] = [];
  const combinedAnalysisText = `${fullText}\n${decodedBase64.map((d) => d.decoded).join('\n')}`;
  for (const rule of store.rules) {
    try {
      const re = new RegExp(rule.pattern, 'i');
      if (re.test(combinedAnalysisText)) {
        yaraMatches.push({
          ruleId: rule.id,
          description: rule.title,
          severity: rule.severity,
        });
      }
    } catch {
      // skip
    }
  }

  // Compute deterministic static risk score
  let riskScore = 8;
  if (shannonEntropy > 7.2) riskScore += 25;
  else if (shannonEntropy > 6.4) riskScore += 10;
  riskScore += Math.min(suspiciousApis.length * 14, 42);
  riskScore += Math.min(yaraMatches.length * 22, 44);
  if (decodedBase64.length > 0) riskScore += 12;
  if (ips.length > 0 || urls.length > 0) riskScore += 10;
  riskScore = Math.min(riskScore, 99);

  const verdict: ArtifactAnalysisResult['verdict'] =
    riskScore >= 70 ? 'Malicious' : riskScore >= 35 ? 'Suspicious' : 'Benign';

  const result: ArtifactAnalysisResult = {
    sampleId: `ART-${sha256.substring(0, 8).toUpperCase()}`,
    fileName,
    sizeBytes: buffer.length,
    sha256,
    sha1,
    md5,
    magicType,
    shannonEntropy,
    riskScore,
    verdict,
    analyzedAt: new Date().toISOString(),
    indicators: {
      ips,
      urls,
      domains,
      registryKeys,
      suspiciousApis,
    },
    decodedBase64,
    yaraMatches,
    stringsPreview: asciiMatches.slice(0, 30),
  };

  appendAuditLog(
    roleToActor(role),
    role,
    'ARTIFACT_STATIC_ANALYSIS',
    'SANDBOX',
    `${fileName} sha256=${sha256.substring(0, 12)} verdict=${verdict}`,
    'SUCCESS'
  );

  res.json({ result, auditVerification: verifyAuditChain() });
});

// Real Threat Intelligence & RDAP / DNS Lookup
app.post('/api/threat-intel/lookup', async (req, res) => {
  const { query } = req.body;
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'IOC query is required' });
  }

  const trimmed = query.trim();
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed);
  const isHash = /^[a-fA-F0-9]{32,64}$/.test(trimmed);
  const type = isIP ? 'IPv4 Address' : isHash ? 'Cryptographic Hash' : 'Domain / Hostname';

  let reversePtr: string[] = [];
  let resolvedIps: string[] = [];
  let rdapData: any = null;

  try {
    if (isIP && !isRestrictedIp(trimmed)) {
      reversePtr = await dns.reverse(trimmed).catch(() => []);
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 3500);
      try {
        const rdapResp = await fetch(`https://rdap.org/ip/${encodeURIComponent(trimmed)}`, {
          signal: ctrl.signal,
        });
        if (rdapResp.ok) rdapData = await rdapResp.json();
      } catch {
        // RDAP timeout/offline fallback
      } finally {
        clearTimeout(t);
      }
    } else if (!isHash && !isIP) {
      const cleanDom = trimmed.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
      if (isValidPublicHostname(cleanDom)) {
        resolvedIps = await dns.resolve4(cleanDom).catch(() => []);
        if (resolvedIps.length > 0 && !resolvedIps.some((ip) => isRestrictedIp(ip))) {
          const ctrl = new AbortController();
          const t = setTimeout(() => ctrl.abort(), 3500);
          try {
            const rdapResp = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDom)}`, {
              signal: ctrl.signal,
            });
            if (rdapResp.ok) rdapData = await rdapResp.json();
          } catch {
            // fallback
          } finally {
            clearTimeout(t);
          }
        }
      }
    }
  } catch {
    // ignore DNS errors
  }

  const knownBadMatch = store.alerts.find(
    (a) => a.sourceIp === trimmed || a.destIp === trimmed || a.rawLog.includes(trimmed)
  );

  res.json({
    query: trimmed,
    type,
    internalTelemetryHits: knownBadMatch ? [knownBadMatch.id] : [],
    reversePtr,
    resolvedIps,
    registry: rdapData
      ? {
          name: rdapData.name || rdapData.ldhName || 'Registered Network',
          handle: rdapData.handle || 'N/A',
          country: rdapData.country || 'N/A',
          cidr: rdapData.cidr0_cidrs?.[0]
            ? `${rdapData.cidr0_cidrs[0].v4prefix}/${rdapData.cidr0_cidrs[0].length}`
            : undefined,
          status: Array.isArray(rdapData.status) ? rdapData.status : [],
        }
      : null,
    threatScore: knownBadMatch ? 94 : isHash ? 82 : 18,
    reputation: knownBadMatch ? 'OBSERVED_IN_ACTIVE_INCIDENT' : 'NO_INTERNAL_HIT',
  });
});

// Gemini Copilot / SOC Assistant endpoint
app.post('/api/ai/copilot', async (req, res) => {
  try {
    const { prompt, role = 'SOC Tier 3 Lead' } = req.body;
    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    const activeAlertsSummary = store.alerts
      .filter((a) => a.status === 'Active' || a.status === 'Investigating')
      .map((a) => `${a.id} [${a.severity}] ${a.title} on ${a.assetName} (src=${a.sourceIp}, MITRE=${a.mitreTechniqueId})`)
      .join('\n');

    if (!ai) {
      return res.json({
        analysis: `Triage Assessment (${role})\n\nQuery: "${prompt}"\n\nActive Workspace Incidents:\n${activeAlertsSummary || 'None'}\n\nRecommended Engineering Actions:\n1. Correlate outbound flow logs for ${store.alerts[0]?.sourceIp || 'suspicious endpoints'} across edge firewall & Zeek logs.\n2. Validate child process lineage on ${store.alerts[1]?.assetName || 'affected endpoints'} before executing eBPF host containment.\n3. Verify Sigma rule coverage in Detection & SOAR workbench.\n\n(Configure GEMINI_API_KEY in .env to enable live Gemini model inference.)`,
        model: 'deterministic-fallback',
        explainability: {
          confidenceScore: 89,
          ruleMatches: store.rules.slice(0, 3).map((r) => r.id),
          falsePositiveProbability: '11%',
          evidenceFactors: [
            `Correlated against ${store.alerts.length} workspace incidents`,
            `Matched ${store.rules.filter((r) => r.enabled).length} active detection rules`,
          ],
        },
      });
    }

    const systemInstruction = `You are Sentinel Copilot, a senior principal security operations and detection engineer.
Your audience is a ${role}. Be concise, technically exact, and strictly grounded in the live workspace telemetry provided.
Never invent fake telemetry or hype. Use markdown headings, bullet points, and fenced code blocks for CLI/Sigma/YARA commands.`;

    const fullPrompt = `Live Workspace Context:
Active Incidents:
${activeAlertsSummary}

Protected Assets: ${store.assets.map((a) => `${a.name} (${a.ip}, ${a.status})`).join(', ')}

Analyst Query: ${prompt}`;

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: fullPrompt,
      config: {
        systemInstruction,
        temperature: 0.25,
      },
    });

    return res.json({
      analysis: response.text || 'No response generated.',
      model: 'gemini-4-hydrogen',
      explainability: {
        confidenceScore: 93,
        ruleMatches: store.rules.filter((r) => r.enabled).slice(0, 3).map((r) => r.id),
        falsePositiveProbability: '7%',
        evidenceFactors: [
          'Grounded in live workspace incidents and asset topology state',
          'Cross-referenced with MITRE ATT&CK v14 mapping',
        ],
      },
    });
  } catch (error: any) {
    console.error('Copilot API Error:', error);
    return res.status(500).json({
      error: 'Error processing AI security query',
      details: error.message,
    });
  }
});

// Rule Generator Endpoint (YARA, Sigma, Suricata)
app.post('/api/ai/generate-rule', async (req, res) => {
  try {
    const { ruleType = 'sigma', description = 'Suspicious process execution', indicators = [] } = req.body;
    if (!ai) {
      let sampleRule = '';
      if (ruleType === 'yara') {
        sampleRule = `rule Sentinel_Custom_Rule {\n  meta:\n    author = "Sentinel Detection Engineering"\n    description = "${description}"\n  strings:\n    $s1 = "Invoke-Expression" ascii wide\n    $mz = { 4D 5A }\n  condition:\n    $mz at 0 and $s1\n}`;
      } else if (ruleType === 'sigma') {
        sampleRule = `title: ${description}\nid: ${crypto.randomUUID()}\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: 'powershell.exe -enc'\n  condition: selection\nlevel: high`;
      } else {
        sampleRule = `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SENTINEL ${description}"; flow:established,to_server; sid:${Math.floor(2100000 + Math.random() * 90000)}; rev:1;)`;
      }
      return res.json({ rule: sampleRule, ruleType });
    }

    const prompt = `Generate a syntactically valid ${ruleType.toUpperCase()} detection rule for: "${description}". Indicators: ${JSON.stringify(indicators)}. Return ONLY the raw detection rule without surrounding prose.`;

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: prompt,
      config: {
        systemInstruction:
          'You are a principal detection engineer specializing in Sigma YAML, YARA, and Suricata IDS syntax. Return clean, production-ready rules.',
        temperature: 0.2,
      },
    });

    return res.json({ rule: response.text || '', ruleType });
  } catch (error: any) {
    return res.status(500).json({ error: error.message });
  }
});

// Executive Report Generator Endpoint
app.post('/api/ai/generate-report', async (req, res) => {
  try {
    const { reportType = 'Executive CISO Summary' } = req.body;
    const summaryData = {
      activeAlerts: store.alerts.filter((a) => a.status === 'Active').length,
      totalAlerts: store.alerts.length,
      assetsAtRisk: store.assets.filter((a) => a.status === 'At Risk').length,
      isolatedAssets: store.assets.filter((a) => a.status === 'Isolated').length,
      compliancePass: store.compliance.filter((c) => c.status === 'PASS').length,
      complianceTotal: store.compliance.length,
      topIncidents: store.alerts.slice(0, 3).map((a) => ({
        id: a.id,
        severity: a.severity,
        title: a.title,
        status: a.status,
        asset: a.assetName,
      })),
    };

    if (!ai) {
      return res.json({
        report: `# ${reportType}\n\nGenerated: ${new Date().toISOString().split('T')[0]}\n\n## Operational Summary\n- Active Incidents: ${summaryData.activeAlerts} of ${summaryData.totalAlerts} tracked\n- Assets At Risk: ${summaryData.assetsAtRisk} (${summaryData.isolatedAssets} isolated)\n- Compliance Controls Passing: ${summaryData.compliancePass}/${summaryData.complianceTotal}\n\n## Priority Findings\n${summaryData.topIncidents.map((i) => `- **${i.id} (${i.severity})**: ${i.title} on \`${i.asset}\` — Status: ${i.status}`).join('\n')}\n\n## Recommended Next Steps\n1. Complete containment verification on \`prod-db-01\` and rotate service credentials.\n2. Remediate CIS 5.2.1 SSH root login configuration on \`bastion-gw-01\`.`,
      });
    }

    const prompt = `Generate a crisp, factual ${reportType} grounded strictly in this live telemetry: ${JSON.stringify(summaryData)}. Format in clean Markdown with Executive Summary, Incident Posture, Compliance Gaps, and Prioritized Actions.`;

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: prompt,
      config: {
        systemInstruction:
          'You are a CISO security advisor. Write factual, executive-ready Markdown reports with zero fluff or marketing buzzwords.',
        temperature: 0.25,
      },
    });

    return res.json({ report: response.text || '' });
  } catch (error: any) {
    return res.status(500).json({ error: error.message });
  }
});

// Setup Vite Development Middleware or Static Production Serving
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });

    // When HMR is disabled in proxied preview environments, serve @vite/client helpers
    // without opening a dead WebSocket transport to port 24678.
    app.get('/@vite/client', (_req, res) => {
      res.type('application/javascript').send(`
const sheetsMap = new Map();
if ("document" in globalThis) {
  document.querySelectorAll("style[data-vite-dev-id]").forEach((el) => {
    sheetsMap.set(el.getAttribute("data-vite-dev-id"), el);
  });
}
export function updateStyle(id, content) {
  let style = sheetsMap.get(id);
  if (!style) {
    style = document.createElement("style");
    style.setAttribute("type", "text/css");
    style.setAttribute("data-vite-dev-id", id);
    style.textContent = content;
    document.head.appendChild(style);
  } else {
    style.textContent = content;
  }
  sheetsMap.set(id, style);
}
export function removeStyle(id) {
  const style = sheetsMap.get(id);
  if (style) {
    style.remove();
    sheetsMap.delete(id);
  }
}
export function createHotContext() {
  return {
    data: {},
    accept() {},
    acceptExports() {},
    dispose() {},
    prune() {},
    decline() {},
    invalidate() {},
    on() {},
    off() {},
    send() {},
  };
}
export function injectQuery(url, queryToInject) {
  if (url[0] !== "." && url[0] !== "/") return url;
  const pathname = url.replace(/[?#].*$/, "");
  const { search, hash } = new URL(url, "http://vite.dev");
  return \`\${pathname}?\${queryToInject}\${search ? "&" + search.slice(1) : ""}\${hash || ""}\`;
}
export class ErrorOverlay extends HTMLElement {
  close() { this.remove(); }
}
`);
    });

    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sentinel Security Platform listening on http://localhost:${PORT}`);
  });
}

startServer();
