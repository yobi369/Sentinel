# SentinelAI

**Cloud SIEM, Attack Surface Inspector & Autonomous Incident Response Platform**

SentinelAI is a full-stack TypeScript security operations platform built with React, Tailwind CSS, Express, Node.js network/crypto primitives, and the server-side `@google/genai` SDK.

---

## Core Capabilities

- **Incident Triage & SOAR Playbooks**: High-density triage queue with persistent incident states (`Active`, `Investigating`, `Mitigated`, `Closed`), analyst notes, eBPF host quarantine controls, and automated response playbooks.
- **Detection Engineering & Live Rule Tester**: Manage Sigma, YARA, and Suricata signatures, benchmark regex patterns against ingested telemetry in milliseconds (protected against catastrophic backtracking), and deploy custom detection rules.
- **External Telemetry Webhook Collector (`/api/v1/ingest/webhook`)**: Stream syslog, Suricata, Zeek, or application JSON events from external infrastructure into SentinelAI with optional Bearer/header key verification and real-time Server-Sent Events (`/api/stream`) UI updates.
- **Live Attack Surface & Posture Inspector**: Executes real DNS (`A`, `MX`, `SPF`, `DMARC`) resolution, live port-443 X.509 TLS certificate handshake auditing, and HTTP security header inspections (`HSTS`, `CSP`, `X-Content-Type-Options`, server banner leaks) with copyable `openssl`/`curl`/`dig` verification commands and private-IP egress protection.
- **Static Artifact & Payload Analyzer**: Computes SHA-256, SHA-1, and MD5 digests, Shannon byte entropy (`0–8 bits/byte`), magic-byte file identification, automatic Base64 payload decoding, IOC extraction, and rule matching on uploaded files or pasted scripts.
- **MITRE ATT&CK Coverage & RDAP/DNS IOC Enrichment**: Enterprise technique coverage matrix paired with reverse PTR, DNS, and RDAP network registry lookups.
- **Cryptographic SHA-256 Hash-Chained Audit Ledger**: Every mutation (triage updates, playbook executions, rule changes, scope authorizations, host isolations) appends a chained SHA-256 record verifiable via `/api/audit/verify`.
- **Security Copilot & Report Compiler**: Server-side Gemini (`gemini-4-hydrogen`) assistant grounded in live workspace state for triage guidance, Sigma/YARA/Suricata rule synthesis, and Markdown CISO/post-mortem reports.

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment variables
Copy `.env.example` to `.env` and configure your secrets:
```bash
cp .env.example .env
```
- `GEMINI_API_KEY`: Optional Google Gemini API key for live Copilot inference (falls back cleanly to deterministic triage output if unset).
- `SENTINEL_INGEST_KEY`: Optional shared secret required on `Authorization: Bearer <key>` or `X-Sentinel-Ingest-Key` for `/api/v1/ingest/webhook`.

### 3. Run in development
```bash
npm run dev
```
The server starts on `http://localhost:3000`.

### 4. Verify types, tests, and production build
```bash
npm run lint
npm test
npm run build
npm start
```

### 5. Container deployment
```bash
docker build -t sentinel-ai .
docker run -p 3000:3000 -e GEMINI_API_KEY=your_key sentinel-ai
```

---

## Streaming External Logs via Webhook

Forward logs from any server, CI pipeline, or collector into SentinelAI:

```bash
curl -X POST http://localhost:3000/api/v1/ingest/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "source": "edr",
    "host": "prod-api-03",
    "raw": "sysmon EventID=4688 CommandLine=\"powershell.exe -nop -w hidden -enc aW52b2tlLWV4cHJlc3Npb24=\""
  }'
```

When an active rule matches, SentinelAI creates an incident, appends a SHA-256 audit entry, and pushes an SSE update to connected dashboards.

---

## Security Controls Built In

- Server-side secret isolation (`GEMINI_API_KEY` and `SENTINEL_INGEST_KEY` never exposed to browser bundles)
- Outbound IP/hostname restriction blocking loopback, RFC1918, and link-local cloud metadata (`169.254.0.0/16`) before DNS/TLS/HTTP probing
- Pattern length and nested-quantifier validation on custom detection rules
- Sliding-window rate limiting on `/api/*`, `/api/ai/*`, and `/api/scanner/*`
- Timing-safe secret comparison (`crypto.timingSafeEqual`) for webhook ingestion authentication
