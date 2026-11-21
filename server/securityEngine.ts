import crypto from 'crypto';
import type { AuditLogEntry } from '../src/types';

export function computeEntryHash(
  prevHash: string,
  sequence: number,
  timestamp: string,
  actor: string,
  action: string,
  target: string
): string {
  const payload = `${prevHash}|${sequence}|${timestamp}|${actor}|${action}|${target}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

export function verifyAuditChainEntries(entriesNewestFirst: AuditLogEntry[]): {
  valid: boolean;
  checkedCount: number;
  headHash: string;
} {
  const chronological = [...entriesNewestFirst].reverse();
  let expectedPrev = '0'.repeat(64);
  for (const entry of chronological) {
    if (entry.prevHash !== expectedPrev) {
      return {
        valid: false,
        checkedCount: chronological.length,
        headHash: entriesNewestFirst[0]?.hash || '',
      };
    }
    const recomputed = computeEntryHash(
      entry.prevHash,
      entry.sequence,
      entry.timestamp,
      entry.actor,
      entry.action,
      entry.target
    );
    if (recomputed !== entry.hash) {
      return {
        valid: false,
        checkedCount: chronological.length,
        headHash: entriesNewestFirst[0]?.hash || '',
      };
    }
    expectedPrev = entry.hash;
  }
  return {
    valid: true,
    checkedCount: chronological.length,
    headHash: entriesNewestFirst[0]?.hash || '',
  };
}

export function isRestrictedIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8 RFC1918
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-local / Cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // Multicast & reserved
  return false;
}

export function isValidPublicHostname(host: string): boolean {
  if (!host || host.length > 253) return false;
  if (host.includes('[') || host.includes(']') || host.includes(':')) return false;
  if (!host.includes('.')) return false;
  if (host.endsWith('.local') || host.endsWith('.internal')) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
    host
  );
}

export function validateSafeRegex(pattern: string): { valid: boolean; reason?: string } {
  if (!pattern || typeof pattern !== 'string') {
    return { valid: false, reason: 'Pattern is required' };
  }
  if (pattern.length > 256) {
    return { valid: false, reason: 'Pattern exceeds 256-character complexity limit' };
  }
  // Reject classic catastrophic backtracking nested quantifiers
  if (/\((?:[^()]*[+*][^()]*)\)[+*{]/.test(pattern)) {
    return { valid: false, reason: 'Nested quantifiers are disallowed to prevent ReDoS' };
  }
  try {
    new RegExp(pattern, 'i');
    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}

export function calculateShannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < buf.length; i++) {
    counts[buf[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / buf.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function detectMagicBytes(buf: Buffer, fileName: string): string {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    return 'PE32/PE64 Windows Executable (MZ)';
  }
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return 'ELF Executable (Linux/Unix)';
  }
  if (buf.length >= 4 && buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) {
    return 'PDF Document (%PDF)';
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    return 'ZIP / OOXML / JAR Archive (PK)';
  }
  if (fileName.endsWith('.ps1')) return 'PowerShell Script (.ps1)';
  if (fileName.endsWith('.sh')) return 'POSIX Shell Script (.sh)';
  if (fileName.endsWith('.json') || fileName.endsWith('.log')) return 'Structured Telemetry / Log Text';
  return 'UTF-8 Text / Script Payload';
}

export function timingSafeSecretEquals(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
