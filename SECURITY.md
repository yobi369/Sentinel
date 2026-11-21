# Security and Production Readiness

## Current deployment classification

SentinelAI is under active development. It must be treated as a lab and controlled-pilot platform, not as a production SIEM/SOAR or an authoritative incident-response system.

## Safeguards introduced in security/production-foundation

- External webhook ingestion is disabled unless `SENTINEL_INGEST_KEY` is configured with at least 32 characters.
- A missing or undersized collector secret returns HTTP 503; invalid credentials return HTTP 401.
- Playbook execution and host isolation/restoration fail closed with HTTP 501 until a real response adapter is configured. No incident is marked mitigated and no asset is marked isolated by these placeholder endpoints.
- Workspace reset is unavailable when `NODE_ENV=production`.

## Critical release gates

These are blockers, not optional enhancements:

1. **Identity and authorization:** implement server-verified authentication, server-side RBAC and tenant-scoped authorization. Never trust a role or actor identity supplied in a request body.
2. **Data durability:** replace the local JSON file with a transactional database, migrations, retention policy, backups and tested restore procedures.
3. **Collector security:** use per-tenant/per-agent credentials, rotation, revocation, replay protection, payload schemas, size limits and durable queueing.
4. **Detection correctness:** execute Sigma, YARA and Suricata rules using their actual engines or explicitly label supported rules as regex approximations. Add rule fixtures, regression tests and false-positive/false-negative measurement.
5. **Incident response:** integrate supported EDR, firewall or cloud control-plane adapters. Require authorization for disruptive actions and verify the external system's result before changing incident state.
6. **Audit integrity:** cover all security-relevant fields, use a protected signing key or external append-only destination, and test truncation, reordering and rewrite attacks.
7. **Network scanning:** enforce explicit customer-owned scope, resolve and validate every destination address, block private/reserved/link-local ranges after DNS resolution, and defend against DNS rebinding and redirects.
8. **Operational resilience:** add structured logs, metrics, health/readiness checks, queue back-pressure, bounded retention, rate limiting across instances and documented recovery objectives.
9. **Application security:** add server-side input schemas, CSRF protections where cookie sessions are used, secure headers/CSP, dependency scanning, secret scanning and a production error handler.
10. **Validation:** run unit, integration, authorization, load, backup/restore and controlled attack-simulation tests before any customer pilot.

## Safe pilot rules

- Use synthetic or explicitly authorized lab telemetry first.
- Do not point scanners at third-party infrastructure without written authorization.
- Do not enable automatic containment until an adapter has passed integration tests and rollback drills.
- Treat AI output as analyst assistance, never as evidence. Every conclusion must link to source events and reproducible observations.
- Preserve original event payloads and timestamps; record parsing and enrichment separately.

## Collector secret generation

Generate a unique secret for each environment and store it in the deployment platform's secret manager:

```bash
openssl rand -hex 32
```

Never commit real credentials to Git.
