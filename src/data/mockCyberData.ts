import {
  IncidentAlert,
  Playbook,
  Asset,
  Vulnerability,
  MitreTechnique,
  ComplianceCheck,
  DetectionRule,
  TelemetryEvent,
} from '../types';

export const INITIAL_ALERTS: IncidentAlert[] = [
  {
    id: 'INC-4091',
    title: 'Cobalt Strike Beacon Egress Pattern',
    severity: 'Critical',
    status: 'Active',
    sourceIp: '185.220.101.5',
    destIp: '10.0.1.45',
    assetName: 'prod-db-01',
    mitreTechniqueId: 'T1071.001',
    mitreTechniqueName: 'Application Layer Protocol: Web Protocols',
    timestamp: '2026-11-20 22:41:04',
    description:
      'Suricata signature 2024109 flagged periodic HTTPS POST beacons with 60s +/- 12% jitter targeting unverified ASN endpoint.',
    rawLog:
      '2026-11-20T22:41:04.112Z suricata[4102]: [1:2024109:3] ET MALWARE Cobalt Strike Beacon [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 10.0.1.45:44912 -> 185.220.101.5:443',
    ruleMatched: 'SURICATA-ET-2024109',
    assignee: 'm.chen@sentinel.io',
    triageNotes: 'TLS JA3/JARM matches known malleable C2 profile. Pending host containment approval.',
    xaiExplanation: {
      confidenceScore: 96,
      evidenceFactors: [
        'TLS JARM fingerprint matches malleable C2 listener signature',
        'Inter-arrival beacon interval exhibits deterministic 60s jitter distribution',
        'Destination ASN lacks reverse PTR or valid corporate allowlist entry',
      ],
      falsePositiveProbability: '4%',
      impactRating: 'High — Lateral exposure to primary PostgreSQL cluster',
    },
    recommendedPlaybookId: 'PB-ISOLATE-01',
    playbookExecuted: false,
  },
  {
    id: 'INC-4088',
    title: 'Encoded PowerShell Child Process Execution',
    severity: 'High',
    status: 'Active',
    sourceIp: '10.0.2.14',
    destIp: '10.0.2.1',
    assetName: 'fin-ws-08',
    mitreTechniqueId: 'T1059.001',
    mitreTechniqueName: 'Command and Scripting Interpreter: PowerShell',
    timestamp: '2026-11-20 22:18:42',
    description:
      'Sysmon Event ID 1 / Windows 4688 matched base64-encoded PowerShell payload spawned from non-interactive cmd.exe shell.',
    rawLog:
      '2026-11-20T22:18:42.004Z sysmon[1840]: EventID=4688 Host=fin-ws-08 User=CORP\\j.doe Parent=cmd.exe CommandLine="powershell.exe -nop -w hidden -e aW52b2tlLWV4cHJlc3Npb24gKG5ldy1vYmplY3QgbmV0LndlYmNsaWVudCkud2FpdA=="',
    ruleMatched: 'SIGMA-WIN-PS-ENCODED',
    assignee: 'Unassigned',
    xaiExplanation: {
      confidenceScore: 92,
      evidenceFactors: [
        'Decoded UTF-16LE base64 payload invokes Net.WebClient expression',
        'Hidden window flag (-w hidden) used under standard domain user context',
        'Parent process chain cmd.exe -> powershell.exe deviates from baseline',
      ],
      falsePositiveProbability: '8%',
      impactRating: 'Medium — Endpoint execution & potential staging',
    },
    recommendedPlaybookId: 'PB-KILLPROCS-02',
    playbookExecuted: false,
  },
  {
    id: 'INC-4082',
    title: 'Distributed SSH Password Spraying',
    severity: 'High',
    status: 'Investigating',
    sourceIp: '194.26.29.110',
    destIp: '10.0.1.10',
    assetName: 'bastion-gw-01',
    mitreTechniqueId: 'T1110.003',
    mitreTechniqueName: 'Brute Force: Password Spraying',
    timestamp: '2026-11-20 21:54:15',
    description:
      'Zeek SSH analyzer observed 452 failed authentication attempts across 30 distinct principals within a 120-second window.',
    rawLog:
      '2026-11-20T21:54:15.891Z zeek_ssh: id.orig_h=194.26.29.110 id.resp_h=10.0.1.10 id.resp_p=22 auth_success=F auth_attempts=452 client=SSH-2.0-libssh_0.9.6',
    ruleMatched: 'ZEEK-SSH-SPRAY-03',
    assignee: 'a.patel@sentinel.io',
    triageNotes: 'Edge ACL rule pushed; monitoring for rotating source CIDR.',
    xaiExplanation: {
      confidenceScore: 98,
      evidenceFactors: [
        'Sequential dictionary sweep across administrative usernames (root, deploy, ubuntu)',
        'Source IP listed in Spamhaus DROP & AbuseIPDB high-confidence feeds',
        'Zero successful handshakes recorded',
      ],
      falsePositiveProbability: '2%',
      impactRating: 'Medium — Perimeter authentication noise',
    },
    recommendedPlaybookId: 'PB-BLOCKIP-03',
    playbookExecuted: true,
  },
  {
    id: 'INC-4075',
    title: 'RC4 Kerberoasting Ticket Request Spike',
    severity: 'Medium',
    status: 'Mitigated',
    sourceIp: '10.0.3.88',
    destIp: '10.0.3.5',
    assetName: 'ad-dc-01',
    mitreTechniqueId: 'T1558.003',
    mitreTechniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    timestamp: '2026-11-20 20:45:10',
    description:
      'Event ID 4769 recorded TGS requests specifying RC4-HMAC (0x17) encryption downgrade across multiple MSSQL SPNs.',
    rawLog:
      '2026-11-20T20:45:10.432Z win_sec[4769]: TargetName=MSSQLSvc/db01.corp:1433 TicketEncryptionType=0x17 ClientAddress=10.0.3.88 Result=0x0',
    ruleMatched: 'SIGMA-AD-KERBEROAST',
    assignee: 'm.chen@sentinel.io',
    xaiExplanation: {
      confidenceScore: 89,
      evidenceFactors: [
        'Explicit encryption downgrade to RC4 (0x17) instead of AES256-CTS',
        'Burst of 14 SPN queries within 8 seconds from workstation subnet',
      ],
      falsePositiveProbability: '11%',
      impactRating: 'Medium — Offline service credential cracking risk',
    },
    recommendedPlaybookId: 'PB-REVOKETOKENS-04',
    playbookExecuted: true,
  },
  {
    id: 'INC-4069',
    title: 'Kubernetes Anonymous Pod Exec Attempt',
    severity: 'Medium',
    status: 'Closed',
    sourceIp: '10.0.5.12',
    destIp: '10.0.5.1',
    assetName: 'k8s-cluster-prod',
    mitreTechniqueId: 'T1609',
    mitreTechniqueName: 'Container Administration Command',
    timestamp: '2026-11-20 19:30:18',
    description:
      'Kubernetes API audit log captured denied pods/exec creation request from unauthenticated anonymous principal.',
    rawLog:
      '2026-11-20T19:30:18.110Z kube-apiserver: auditID=91b4 verb=create resource=pods/exec user=system:anonymous responseStatus=403 uri=/api/v1/namespaces/default/pods/app-frontend-79b/exec',
    ruleMatched: 'SIGMA-K8S-ANON-EXEC',
    assignee: 's.okafor@sentinel.io',
    xaiExplanation: {
      confidenceScore: 94,
      evidenceFactors: [
        'API server enforced RBAC denial (HTTP 403)',
        'Source pod telemetry verified clean after ephemeral recycle',
      ],
      falsePositiveProbability: '6%',
      impactRating: 'Low — Blocked by cluster admission policy',
    },
    recommendedPlaybookId: 'PB-ISOLATE-01',
    playbookExecuted: true,
  },
];

export const INITIAL_RULES: DetectionRule[] = [
  {
    id: 'SIGMA-WIN-PS-ENCODED',
    format: 'sigma',
    title: 'Encoded PowerShell Execution via Hidden Window',
    target: 'Windows Security / Sysmon 4688',
    severity: 'High',
    pattern: 'powershell\\.exe.*(-e|-enc|-encodedcommand)',
    mitreId: 'T1059.001',
    enabled: true,
    matchCount: 14,
    code: `title: Encoded PowerShell Execution via Hidden Window
id: 9a41b2e8-4901-441a-8812-71c9a0
status: production
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -e '
      - '-encodedcommand'
  condition: selection
level: high`,
  },
  {
    id: 'SURICATA-ET-2024109',
    format: 'suricata',
    title: 'Cobalt Strike Malleable C2 Beacon Activity',
    target: 'Edge / East-West PCAP Sensor',
    severity: 'Critical',
    pattern: '(Cobalt Strike|submit\\.php\\?id=|2024109)',
    mitreId: 'T1071.001',
    enabled: true,
    matchCount: 3,
    code: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
  msg:"ET MALWARE Cobalt Strike Beacon";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"/submit.php?id="; http_uri;
  classtype:trojan-activity;
  sid:2024109; rev:3;
)`,
  },
  {
    id: 'ZEEK-SSH-SPRAY-03',
    format: 'sigma',
    title: 'High-Velocity SSH Password Spray',
    target: 'Zeek SSH Stream',
    severity: 'High',
    pattern: 'zeek_ssh.*auth_success=F.*auth_attempts=([1-9][0-9]{2,})',
    mitreId: 'T1110.003',
    enabled: true,
    matchCount: 28,
    code: `title: High-Velocity SSH Password Spray
id: 3f901a2d-8831-42c1-90b1
status: production
logsource:
  service: zeek_ssh
detection:
  selection:
    auth_success: 'F'
    auth_attempts|gte: 100
  condition: selection
level: high`,
  },
  {
    id: 'SIGMA-AD-KERBEROAST',
    format: 'sigma',
    title: 'Kerberos TGS RC4 Encryption Downgrade',
    target: 'Active Directory Event 4769',
    severity: 'Medium',
    pattern: 'EventID=4769|win_sec\\[4769\\].*TicketEncryptionType=0x17',
    mitreId: 'T1558.003',
    enabled: true,
    matchCount: 6,
    code: `title: Kerberos TGS RC4 Encryption Downgrade
id: 72c8b019-11e4-49b0-b122
status: production
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  condition: selection
level: medium`,
  },
  {
    id: 'YARA-MEM-INJECT-01',
    format: 'yara',
    title: 'In-Memory PE & VirtualAllocEx RWX Heuristic',
    target: 'Volatile Memory / File Artifacts',
    severity: 'Critical',
    pattern: '(VirtualAllocEx|NtCreateThreadEx|Invoke-Expression|PAGE_EXECUTE_READWRITE)',
    mitreId: 'T1055',
    enabled: true,
    matchCount: 5,
    code: `rule Win32_InMemory_Injection_Heuristic {
  meta:
    author = "Sentinel Detection Engineering"
    mitre = "T1055"
    severity = "Critical"
  strings:
    $api1 = "VirtualAllocEx" ascii wide
    $api2 = "NtCreateThreadEx" ascii wide
    $prot = "PAGE_EXECUTE_READWRITE" ascii
  condition:
    uint16(0) == 0x5A4D and (all of ($api*) or $prot)
}`,
  },
];

export const INITIAL_TELEMETRY: TelemetryEvent[] = [
  {
    id: 'EVT-1001',
    timestamp: '2026-11-20T22:41:04.112Z',
    source: 'suricata',
    host: 'prod-db-01',
    raw: '2026-11-20T22:41:04.112Z suricata[4102]: [1:2024109:3] ET MALWARE Cobalt Strike Beacon {TCP} 10.0.1.45:44912 -> 185.220.101.5:443',
    matchedRuleId: 'SURICATA-ET-2024109',
  },
  {
    id: 'EVT-1002',
    timestamp: '2026-11-20T22:18:42.004Z',
    source: 'edr',
    host: 'fin-ws-08',
    raw: '2026-11-20T22:18:42.004Z sysmon[1840]: EventID=4688 Host=fin-ws-08 CommandLine="powershell.exe -nop -w hidden -e aW52b2tlLWV4cHJlc3Npb24="',
    matchedRuleId: 'SIGMA-WIN-PS-ENCODED',
  },
  {
    id: 'EVT-1003',
    timestamp: '2026-11-20T21:54:15.891Z',
    source: 'zeek',
    host: 'bastion-gw-01',
    raw: '2026-11-20T21:54:15.891Z zeek_ssh: id.orig_h=194.26.29.110 id.resp_h=10.0.1.10 auth_success=F auth_attempts=452',
    matchedRuleId: 'ZEEK-SSH-SPRAY-03',
  },
  {
    id: 'EVT-1004',
    timestamp: '2026-11-20T21:12:09.330Z',
    source: 'syslog',
    host: 'web-frontend-stage',
    raw: '2026-11-20T21:12:09.330Z nginx: 10.0.2.1 - - "GET /api/health HTTP/1.1" 200 64 "-" "kube-probe/1.30"',
  },
  {
    id: 'EVT-1005',
    timestamp: '2026-11-20T20:45:10.432Z',
    source: 'syslog',
    host: 'ad-dc-01',
    raw: '2026-11-20T20:45:10.432Z win_sec[4769]: TargetName=MSSQLSvc/db01.corp:1433 TicketEncryptionType=0x17 ClientAddress=10.0.3.88',
    matchedRuleId: 'SIGMA-AD-KERBEROAST',
  },
];

export const INITIAL_PLAYBOOKS: Playbook[] = [
  {
    id: 'PB-ISOLATE-01',
    name: 'Host Network Quarantine (eBPF)',
    description:
      'Applies eBPF egress/ingress drop policy isolating compromised workload while preserving control-plane telemetry tunnel.',
    category: 'Network Isolation',
    actionSteps: [
      'Attach eBPF TC drop filter to non-management interfaces',
      'Snapshot volatile memory & active socket descriptors',
      'Quarantine host identity in EDR control plane',
      'Emit webhook notification to on-call responder',
    ],
    autoTriggerEnabled: true,
    status: 'Ready',
    executionCount: 24,
    lastExecutedAt: '2026-11-20 19:31:02',
  },
  {
    id: 'PB-KILLPROCS-02',
    name: 'Process Tree Termination & Binary Hold',
    description:
      'Terminates malicious child process hierarchy, revokes parent token privileges, and quarantines executable image.',
    category: 'Process Termination',
    actionSteps: [
      'Enumerate full PPID tree via osquery',
      'Terminate tree with SIGKILL / taskkill /F /T',
      'Hash binary (SHA-256) and run YARA signature sweep',
      'Remove scheduled task or Run-key persistence entries',
    ],
    autoTriggerEnabled: false,
    status: 'Ready',
    executionCount: 18,
    lastExecutedAt: '2026-11-20 14:12:40',
  },
  {
    id: 'PB-BLOCKIP-03',
    name: 'Perimeter ACL IP Blackhole',
    description:
      'Pushes automated CIDR block rule to edge WAF and border routers for 72 hours after allowlist validation.',
    category: 'Firewall Filter',
    actionSteps: [
      'Cross-check IP against corporate VPN & partner allowlists',
      'Push deny policy to edge WAF and border iptables',
      'Sync block entry to threat intelligence cache',
      'Record cryptographic proof in audit ledger',
    ],
    autoTriggerEnabled: true,
    status: 'Ready',
    executionCount: 89,
    lastExecutedAt: '2026-11-20 21:55:00',
  },
  {
    id: 'PB-REVOKETOKENS-04',
    name: 'IAM & Kerberos Session Revocation',
    description:
      'Invalidates active OAuth refresh tokens, forces step-up MFA re-authentication, and rotates affected SPN secrets.',
    category: 'Credential Revocation',
    actionSteps: [
      'Revoke active OIDC/OAuth refresh tokens via IdP API',
      'Enforce conditional access step-up MFA challenge',
      'Rotate service principal secret in vault',
      'Invalidate active Kerberos TGT sessions',
    ],
    autoTriggerEnabled: false,
    status: 'Ready',
    executionCount: 12,
    lastExecutedAt: '2026-11-20 20:47:11',
  },
];

export const INITIAL_ASSETS: Asset[] = [
  {
    id: 'AST-101',
    name: 'prod-db-01',
    ip: '10.0.1.45',
    subnet: '10.0.1.0/24',
    type: 'Database Cluster',
    os: 'Ubuntu 24.04 LTS · PostgreSQL 16.4',
    riskScore: 84,
    status: 'At Risk',
    openPorts: [22, 5432, 9100],
    vulnerabilitiesCount: 3,
    lastScanTime: '2026-11-20 22:00:00',
  },
  {
    id: 'AST-102',
    name: 'bastion-gw-01',
    ip: '10.0.1.10',
    subnet: '10.0.1.0/24',
    type: 'Bastion Host',
    os: 'Alpine Linux 3.20 · OpenSSH 9.7',
    riskScore: 62,
    status: 'Protected',
    openPorts: [22, 443],
    vulnerabilitiesCount: 1,
    lastScanTime: '2026-11-20 21:30:00',
  },
  {
    id: 'AST-103',
    name: 'ad-dc-01',
    ip: '10.0.3.5',
    subnet: '10.0.3.0/24',
    type: 'Domain Controller',
    os: 'Windows Server 2022 Datacenter',
    riskScore: 45,
    status: 'Protected',
    openPorts: [53, 88, 389, 445, 636, 3268],
    vulnerabilitiesCount: 2,
    lastScanTime: '2026-11-20 19:15:00',
  },
  {
    id: 'AST-104',
    name: 'k8s-cluster-prod',
    ip: '10.0.5.1',
    subnet: '10.0.5.0/24',
    type: 'Kubernetes Pod',
    os: 'Container-Optimized OS · K8s 1.30',
    riskScore: 28,
    status: 'Protected',
    openPorts: [6443, 10250],
    vulnerabilitiesCount: 0,
    lastScanTime: '2026-11-20 22:10:00',
  },
  {
    id: 'AST-105',
    name: 'web-frontend-stage',
    ip: '10.0.2.14',
    subnet: '10.0.2.0/24',
    type: 'Web Server',
    os: 'Debian 12 · Nginx 1.26.2',
    riskScore: 76,
    status: 'Under Audit',
    openPorts: [80, 443, 8080],
    vulnerabilitiesCount: 4,
    lastScanTime: '2026-11-20 22:15:00',
  },
  {
    id: 'AST-106',
    name: 'fin-ws-08',
    ip: '10.0.2.88',
    subnet: '10.0.2.0/24',
    type: 'Workstation',
    os: 'Windows 11 Enterprise 24H2',
    riskScore: 71,
    status: 'At Risk',
    openPorts: [135, 445],
    vulnerabilitiesCount: 2,
    lastScanTime: '2026-11-20 22:19:00',
  },
];

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    cve: 'CVE-2024-3094',
    title: 'XZ Utils Compromised Upstream Tarball (liblzma)',
    severity: 'Critical',
    cvss: 10.0,
    affectedAsset: 'bastion-gw-01',
    description:
      'Supply-chain hook in liblzma 5.6.0/5.6.1 intercepts RSA_public_decrypt in OpenSSH systemd-linked builds.',
    exploitAvailable: true,
    pocCommand: 'xz --version && ldd $(which sshd) | grep liblzma',
    patchScript: 'apt-get update && apt-get install --only-upgrade -y xz-utils liblzma5 && systemctl restart ssh',
  },
  {
    cve: 'CVE-2023-4863',
    title: 'libwebp Heap Buffer Overflow in Huffman Decoding',
    severity: 'High',
    cvss: 8.8,
    affectedAsset: 'web-frontend-stage',
    description:
      'Out-of-bounds heap write in BuildHuffmanTable() allows remote memory corruption via crafted WebP image upload.',
    exploitAvailable: true,
    pocCommand: 'dpkg -l | grep libwebp',
    patchScript: 'apt-get update && apt-get install --only-upgrade -y libwebp-dev libwebp7',
  },
  {
    cve: 'CVE-2024-21626',
    title: 'runc File Descriptor Leak Container Escape',
    severity: 'High',
    cvss: 8.6,
    affectedAsset: 'k8s-cluster-prod',
    description:
      'Unclosed /sys/fs/cgroup file descriptor in runc <= 1.1.11 permits host filesystem traversal via WORKDIR.',
    exploitAvailable: false,
    pocCommand: 'runc --version',
    patchScript: 'apt-get install --only-upgrade -y containerd.io && systemctl restart containerd',
  },
];

export const MITRE_TACTICS_DATA: MitreTechnique[] = [
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', activeAlertsCount: 1, detectionStatus: 'Blocked', description: 'Adversaries exploit software bugs in internet-facing web servers or APIs.' },
  { id: 'T1110.003', name: 'Password Spraying', tactic: 'Initial Access', activeAlertsCount: 1, detectionStatus: 'Blocked', description: 'Single common password tested across many accounts to avoid lockout thresholds.' },
  { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution', activeAlertsCount: 1, detectionStatus: 'Detected', description: 'Abuse of PowerShell commands and encoded scripts for payload staging.' },
  { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Persistence', activeAlertsCount: 0, detectionStatus: 'Tested', description: 'Abuse of Windows Task Scheduler or cron for recurring execution.' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', activeAlertsCount: 0, detectionStatus: 'Detected', description: 'Kernel or local service vulnerability exploitation to obtain SYSTEM/root.' },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', activeAlertsCount: 1, detectionStatus: 'Detected', description: 'Base64, XOR, or packed binaries used to evade static inspection.' },
  { id: 'T1558.003', name: 'Kerberoasting', tactic: 'Credential Access', activeAlertsCount: 1, detectionStatus: 'Blocked', description: 'Requesting RC4-encrypted TGS tickets for offline cracking.' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', activeAlertsCount: 2, detectionStatus: 'Tested', description: 'Port and service enumeration across internal subnets.' },
  { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement', activeAlertsCount: 0, detectionStatus: 'Detected', description: 'Lateral movement over ADMIN$ or C$ shares using harvested tokens.' },
  { id: 'T1071.001', name: 'Web Protocols C2', tactic: 'Command & Control', activeAlertsCount: 1, detectionStatus: 'Blocked', description: 'HTTPS C2 traffic blending with standard TLS egress.' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', activeAlertsCount: 0, detectionStatus: 'Uncovered', description: 'Stolen data transferred over an established C2 channel.' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', activeAlertsCount: 0, detectionStatus: 'Uncovered', description: 'Ransomware encryption routines targeting shared volumes.' },
];

export const INITIAL_COMPLIANCE: ComplianceCheck[] = [
  {
    id: 'CMP-NIST-01',
    framework: 'NIST 800-53',
    controlId: 'AC-2',
    title: 'Account Management & Least Privilege',
    status: 'PASS',
    score: 96,
    details: 'Automated IAM deprovisioning enforces 30-day inactivity revocation across Okta and AWS IAM.',
    remediation: 'No action required.',
    lastVerified: '2026-11-20 18:00',
  },
  {
    id: 'CMP-NIST-02',
    framework: 'NIST 800-53',
    controlId: 'SI-4',
    title: 'System Monitoring & Intrusion Detection',
    status: 'PASS',
    score: 98,
    details: 'Suricata IDS and Zeek sensors ingest continuous east-west and north-south flow telemetry.',
    remediation: 'No action required.',
    lastVerified: '2026-11-20 22:30',
  },
  {
    id: 'CMP-CIS-01',
    framework: 'CIS Benchmarks',
    controlId: '5.2.1',
    title: 'Ensure SSH Root Login is Disabled',
    status: 'FAIL',
    score: 40,
    details: 'Host bastion-gw-01 permits PermitRootLogin prohibit-password instead of explicit no.',
    remediation: 'Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd.',
    lastVerified: '2026-11-20 21:30',
  },
  {
    id: 'CMP-PCI-01',
    framework: 'PCI-DSS 4.0',
    controlId: 'Req 3.5',
    title: 'Render Primary Account Numbers Unreadable',
    status: 'PASS',
    score: 100,
    details: 'PostgreSQL cluster prod-db-01 enforces AES-256-GCM envelope encryption via KMS.',
    remediation: 'No action required.',
    lastVerified: '2026-11-20 20:00',
  },
  {
    id: 'CMP-ISO-01',
    framework: 'ISO 27001',
    controlId: 'A.8.8',
    title: 'Management of Technical Vulnerabilities',
    status: 'WARN',
    score: 75,
    details: 'CVE-2024-3094 dependency audit pending change-window verification on staging.',
    remediation: 'Execute package upgrade verification and close change ticket.',
    lastVerified: '2026-11-20 21:15',
  },
];
