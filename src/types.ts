export type PostureLevel = 'Normal' | 'Elevated' | 'High' | 'Critical';

export type UserRole =
  | 'SOC Tier 1 Analyst'
  | 'SOC Tier 3 Lead'
  | 'Red Team Assessor'
  | 'Compliance Lead'
  | 'CISO';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface IncidentAlert {
  id: string;
  title: string;
  severity: Severity;
  status: 'Active' | 'Investigating' | 'Mitigated' | 'Closed';
  sourceIp: string;
  destIp: string;
  assetName: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  timestamp: string;
  description: string;
  rawLog: string;
  ruleMatched: string;
  assignee?: string;
  triageNotes?: string;
  xaiExplanation: {
    confidenceScore: number;
    evidenceFactors: string[];
    falsePositiveProbability: string;
    impactRating: string;
  };
  recommendedPlaybookId?: string;
  playbookExecuted?: boolean;
}

export interface DetectionRule {
  id: string;
  format: 'sigma' | 'yara' | 'suricata';
  title: string;
  target: string;
  severity: Severity;
  pattern: string;
  mitreId: string;
  enabled: boolean;
  code: string;
  matchCount: number;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  category:
    | 'Network Isolation'
    | 'Credential Revocation'
    | 'Process Termination'
    | 'Firewall Filter'
    | 'Deception';
  actionSteps: string[];
  autoTriggerEnabled: boolean;
  status: 'Ready' | 'Executing' | 'Completed' | 'Disabled';
  executionCount: number;
  lastExecutedAt?: string;
}

export interface Asset {
  id: string;
  name: string;
  ip: string;
  subnet: string;
  type:
    | 'Web Server'
    | 'Database Cluster'
    | 'Domain Controller'
    | 'Kubernetes Pod'
    | 'Bastion Host'
    | 'Workstation';
  os: string;
  riskScore: number;
  status: 'Protected' | 'At Risk' | 'Isolated' | 'Under Audit';
  openPorts: number[];
  vulnerabilitiesCount: number;
  lastScanTime: string;
}

export interface Vulnerability {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  affectedAsset: string;
  description: string;
  exploitAvailable: boolean;
  pocCommand: string;
  patchScript: string;
}

export interface AttackPathStep {
  id: string;
  stepNumber: number;
  phaseName: string;
  sourceNode: string;
  targetNode: string;
  techniqueUsed: string;
  riskDescription: string;
  remediation: string;
}

export interface SurfaceFinding {
  id: string;
  title: string;
  category: 'TLS' | 'HTTP Header' | 'DNS / Email' | 'Exposure' | 'CVE';
  severity: Severity;
  cvss: number;
  evidence: string;
  verificationCmd: string;
  remediation: string;
}

export interface SurfaceScanResult {
  target: string;
  targetType: 'public-domain' | 'internal-cidr';
  scannedAt: string;
  durationMs: number;
  resolvedIps: string[];
  dns: {
    mxRecords: string[];
    hasSpf: boolean;
    hasDmarc: boolean;
    txtRecordsCount: number;
  };
  tls?: {
    protocol: string;
    cipher: string;
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    authorized: boolean;
  };
  http?: {
    statusCode: number;
    finalUrl: string;
    serverHeader?: string;
    headersPresent: Record<string, string | null>;
  };
  findings: SurfaceFinding[];
  attackPath: AttackPathStep[];
}

export interface ArtifactAnalysisResult {
  sampleId: string;
  fileName: string;
  sizeBytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  magicType: string;
  shannonEntropy: number;
  riskScore: number;
  verdict: 'Malicious' | 'Suspicious' | 'Benign';
  analyzedAt: string;
  indicators: {
    ips: string[];
    urls: string[];
    domains: string[];
    registryKeys: string[];
    suspiciousApis: string[];
  };
  decodedBase64: { encoded: string; decoded: string }[];
  yaraMatches: { ruleId: string; description: string; severity: Severity }[];
  stringsPreview: string[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic:
    | 'Initial Access'
    | 'Execution'
    | 'Persistence'
    | 'Privilege Escalation'
    | 'Defense Evasion'
    | 'Credential Access'
    | 'Discovery'
    | 'Lateral Movement'
    | 'Collection'
    | 'Command & Control'
    | 'Exfiltration'
    | 'Impact';
  activeAlertsCount: number;
  detectionStatus: 'Detected' | 'Blocked' | 'Tested' | 'Uncovered';
  description: string;
}

export interface ComplianceCheck {
  id: string;
  framework: 'NIST 800-53' | 'CIS Benchmarks' | 'PCI-DSS 4.0' | 'ISO 27001';
  controlId: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  score: number;
  details: string;
  remediation: string;
  lastVerified: string;
}

export interface AuditLogEntry {
  id: string;
  sequence: number;
  timestamp: string;
  actor: string;
  role: UserRole;
  action: string;
  module: string;
  target: string;
  status: 'SUCCESS' | 'DENIED' | 'EXECUTED';
  prevHash: string;
  hash: string;
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  model?: string;
  explainability?: {
    confidenceScore: number;
    ruleMatches: string[];
    falsePositiveProbability: string;
    evidenceFactors: string[];
  };
}

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  source: 'suricata' | 'zeek' | 'syslog' | 'kube-audit' | 'edr';
  host: string;
  raw: string;
  matchedRuleId?: string;
}
