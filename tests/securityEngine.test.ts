import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeEntryHash,
  verifyAuditChainEntries,
  isRestrictedIp,
  isValidPublicHostname,
  validateSafeRegex,
  calculateShannonEntropy,
  detectMagicBytes,
  timingSafeSecretEquals,
} from '../server/securityEngine';
import type { AuditLogEntry } from '../src/types';

test('Audit hash chain verifies intact chain and detects tampering', () => {
  const genesis = '0'.repeat(64);
  const h1 = computeEntryHash(genesis, 1, '2026-11-20T00:00:00Z', 'a@sentinel.io', 'LOGIN', 'web');
  const h2 = computeEntryHash(h1, 2, '2026-11-20T00:01:00Z', 'a@sentinel.io', 'ISOLATE', 'prod-db-01');

  const entries: AuditLogEntry[] = [
    {
      id: 'LOG-002',
      sequence: 2,
      timestamp: '2026-11-20T00:01:00Z',
      actor: 'a@sentinel.io',
      role: 'SOC Tier 3 Lead',
      action: 'ISOLATE',
      module: 'ASSETS',
      target: 'prod-db-01',
      status: 'EXECUTED',
      prevHash: h1,
      hash: h2,
    },
    {
      id: 'LOG-001',
      sequence: 1,
      timestamp: '2026-11-20T00:00:00Z',
      actor: 'a@sentinel.io',
      role: 'SOC Tier 3 Lead',
      action: 'LOGIN',
      module: 'AUTH',
      target: 'web',
      status: 'SUCCESS',
      prevHash: genesis,
      hash: h1,
    },
  ];

  assert.equal(verifyAuditChainEntries(entries).valid, true);

  // Tamper with target
  entries[1].target = 'tampered-target';
  assert.equal(verifyAuditChainEntries(entries).valid, false);
});

test('Restricted IP guard blocks loopback, private, and cloud metadata ranges', () => {
  assert.equal(isRestrictedIp('127.0.0.1'), true);
  assert.equal(isRestrictedIp('169.254.169.254'), true);
  assert.equal(isRestrictedIp('10.0.1.45'), true);
  assert.equal(isRestrictedIp('172.16.5.10'), true);
  assert.equal(isRestrictedIp('192.168.1.1'), true);
  assert.equal(isRestrictedIp('0.0.0.0'), true);

  assert.equal(isRestrictedIp('1.1.1.1'), false);
  assert.equal(isRestrictedIp('8.8.8.8'), false);
  assert.equal(isRestrictedIp('140.82.121.4'), false);
});

test('Public hostname validator rejects internal hosts and malformed schemes', () => {
  assert.equal(isValidPublicHostname('github.com'), true);
  assert.equal(isValidPublicHostname('api.cloudflare.com'), true);

  assert.equal(isValidPublicHostname('localhost'), false);
  assert.equal(isValidPublicHostname('metadata.google.internal'), false);
  assert.equal(isValidPublicHostname('[::1]'), false);
  assert.equal(isValidPublicHostname('127.0.0.1:8080'), false);
});

test('ReDoS validator blocks nested quantifiers and excessive lengths', () => {
  assert.equal(validateSafeRegex('(a+)+').valid, false);
  assert.equal(validateSafeRegex('a'.repeat(300)).valid, false);
  assert.equal(validateSafeRegex('powershell\\.exe.*-enc').valid, true);
});

test('Shannon entropy and magic bytes accurately classify artifacts', () => {
  const lowEntropy = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'utf-8');
  assert.equal(calculateShannonEntropy(lowEntropy), 0);

  const highEntropy = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.equal(calculateShannonEntropy(highEntropy), 8);

  assert.equal(
    detectMagicBytes(Buffer.from([0x4d, 0x5a, 0x90, 0x00]), 'payload.bin'),
    'PE32/PE64 Windows Executable (MZ)'
  );
  assert.equal(
    detectMagicBytes(Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 'agent'),
    'ELF Executable (Linux/Unix)'
  );
});

test('Timing-safe secret comparison verifies exact tokens', () => {
  assert.equal(timingSafeSecretEquals('secret-token-123', 'secret-token-123'), true);
  assert.equal(timingSafeSecretEquals('secret-token-123', 'secret-token-124'), false);
  assert.equal(timingSafeSecretEquals('short', 'longer-secret'), false);
});
