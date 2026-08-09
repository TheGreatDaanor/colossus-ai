import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import { scans, scanTargets, findings, type ScanTargetStatus } from '../db/schema.js';

export class ScanValidationError extends Error {}

const MAX_URLS = 100;

export type Scan = typeof scans.$inferSelect;
export type ScanTarget = typeof scanTargets.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type ScanWithTargets = Scan & { targets: (ScanTarget & { findings: Finding[] })[] };

export type StartScanOptions = {
  name?: string;
  userAgent?: string;
};

function defaultScanName(now: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `Scan ${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

function isAllowedUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function dedupe(urls: string[]): string[] {
  return Array.from(new Set(urls));
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

const DISALLOWED_IPV4_RANGES: [string, number][] = [
  ['127.0.0.0', 8], // loopback
  ['10.0.0.0', 8], // private
  ['172.16.0.0', 12], // private
  ['192.168.0.0', 16], // private
  ['169.254.0.0', 16], // link-local, includes the 169.254.169.254 cloud metadata address
];

function isDisallowedIPv4(ip: string): boolean {
  const int = ipv4ToInt(ip);
  if (int === null) return false;

  return DISALLOWED_IPV4_RANGES.some(([base, prefixLength]) => {
    const baseInt = ipv4ToInt(base);
    if (baseInt === null) return false;
    const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
    return (int & mask) === (baseInt & mask);
  });
}

function ipv6ToBigInt(ip: string): bigint | null {
  const doubleColonParts = ip.split('::');
  if (doubleColonParts.length > 2) return null;

  const head = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const tail = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];

  let groups: string[];
  if (doubleColonParts.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    result = (result << 16n) | BigInt(parseInt(group, 16));
  }
  return result;
}

const DISALLOWED_IPV6_PREFIXES: [bigint, number][] = [
  [1n, 128], // ::1 loopback
  [ipv6ToBigInt('fe80::')!, 10], // link-local
  [ipv6ToBigInt('fc00::')!, 7], // unique-local (private)
];

function isDisallowedIPv6(ip: string): boolean {
  const mappedIPv4 = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ip);
  if (mappedIPv4?.[1] !== undefined) return isDisallowedIPv4(mappedIPv4[1]);

  const value = ipv6ToBigInt(ip);
  if (value === null) return false;

  return DISALLOWED_IPV6_PREFIXES.some(([base, prefixLength]) => {
    const shift = BigInt(128 - prefixLength);
    return value >> shift === base >> shift;
  });
}

export function isDisallowedAddress(ip: string): boolean {
  return ip.includes(':') ? isDisallowedIPv6(ip) : isDisallowedIPv4(ip);
}

async function findDisallowedAddress(hostname: string): Promise<string | null> {
  if (isIP(hostname) !== 0) {
    return isDisallowedAddress(hostname) ? hostname : null;
  }

  try {
    const records = await lookup(hostname, { all: true });
    return records.find((record) => isDisallowedAddress(record.address))?.address ?? null;
  } catch {
    // A lookup failure isn't an SSRF signal — let the fetch attempt proceed and fail on its own terms.
    return null;
  }
}

function lowercaseHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

export type FetchImpl = (url: string, init: RequestInit) => Promise<Response>;

export class ScannerService {
  readonly #db: Db;
  readonly #fetchImpl: FetchImpl;
  readonly #timeoutMs: number;
  readonly #concurrency: number;

  constructor(
    db: Db,
    options: { fetchImpl?: FetchImpl; timeoutMs?: number; concurrency?: number } = {},
  ) {
    this.#db = db;
    this.#fetchImpl = options.fetchImpl ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#concurrency = options.concurrency ?? 10;
  }

  async startScan(urls: string[], options: StartScanOptions = {}): Promise<Scan> {
    if (urls.length === 0) throw new ScanValidationError('urls must not be empty');
    if (urls.length > MAX_URLS) throw new ScanValidationError(`urls must not exceed ${MAX_URLS}`);

    const deduped = dedupe(urls);
    const valid = deduped.filter(isAllowedUrl);
    const invalid = deduped.filter((u) => !isAllowedUrl(u));

    const now = new Date();
    const hasValid = valid.length > 0;

    const [scan] = this.#db
      .insert(scans)
      .values({
        name: options.name ?? defaultScanName(now),
        status: hasValid ? 'pending' : 'failed',
        urls: deduped,
        userAgent: options.userAgent ?? null,
        error: hasValid ? null : 'no valid URLs to scan',
        createdAt: now,
        completedAt: hasValid ? null : now,
      })
      .returning()
      .all();
    if (!scan) throw new Error('failed to insert scan');

    for (const url of invalid) {
      this.#db.insert(scanTargets).values({
        scanId: scan.id,
        url,
        status: 'invalid',
        error: 'malformed URL or disallowed scheme',
      }).run();
    }

    if (!hasValid) return scan;

    const targetRows = valid.map((url) =>
      this.#db
        .insert(scanTargets)
        .values({ scanId: scan.id, url, status: 'pending' })
        .returning()
        .get(),
    );

    void this.#runScan(scan.id, targetRows);

    return scan;
  }

  async getScan(id: number): Promise<ScanWithTargets | null> {
    const scan = this.#db.select().from(scans).where(eq(scans.id, id)).get();
    if (!scan) return null;

    const targetRows = this.#db.select().from(scanTargets).where(eq(scanTargets.scanId, id)).all();
    const targets = targetRows.map((target) => ({
      ...target,
      findings: this.#db.select().from(findings).where(eq(findings.scanTargetId, target.id)).all(),
    }));

    return { ...scan, targets };
  }

  async listScans(): Promise<Scan[]> {
    return this.#db.select().from(scans).orderBy(scans.createdAt).all().reverse();
  }

  async #runScan(scanId: number, targetRows: ScanTarget[]): Promise<void> {
    this.#db.update(scans).set({ status: 'running' }).where(eq(scans.id, scanId)).run();

    for (let i = 0; i < targetRows.length; i += this.#concurrency) {
      const batch = targetRows.slice(i, i + this.#concurrency);
      await Promise.all(batch.map((target) => this.#processTarget(target)));
    }

    this.#db
      .update(scans)
      .set({ status: 'completed', completedAt: new Date() })
      .where(eq(scans.id, scanId))
      .run();
  }

  async #processTarget(target: ScanTarget): Promise<void> {
    console.warn(`[scan ${target.scanId}] ${target.url} started`);

    const hostname = new URL(target.url).hostname;
    const disallowedAddress = await findDisallowedAddress(hostname);
    if (disallowedAddress !== null) {
      this.#db
        .update(scanTargets)
        .set({
          status: 'invalid',
          error: `refusing to scan ${hostname}: resolves to disallowed address ${disallowedAddress}`,
        })
        .where(eq(scanTargets.id, target.id))
        .run();

      console.warn(`[scan ${target.scanId}] ${target.url} rejected (disallowed address)`);
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const start = performance.now();

    try {
      const response = await this.#fetchImpl(target.url, {
        redirect: 'manual',
        signal: controller.signal,
      });
      const elapsed = Math.round(performance.now() - start);
      const status: ScanTargetStatus = 'ok';
      const redirectLocation = response.headers.get('location');

      this.#db
        .update(scanTargets)
        .set({
          status,
          statusCode: response.status,
          responseHeaders: lowercaseHeaders(response.headers),
          responseTimeMs: elapsed,
          redirectLocation: redirectLocation ?? null,
        })
        .where(eq(scanTargets.id, target.id))
        .run();

      console.warn(`[scan ${target.scanId}] ${target.url} succeeded`);
    } catch (err) {
      const timedOut = err instanceof Error && err.name === 'AbortError';
      const status: ScanTargetStatus = timedOut ? 'timeout' : 'unreachable';

      this.#db
        .update(scanTargets)
        .set({
          status,
          responseTimeMs: null,
          error: err instanceof Error ? err.message : String(err),
        })
        .where(eq(scanTargets.id, target.id))
        .run();

      console.warn(`[scan ${target.scanId}] ${target.url} ${timedOut ? 'timed-out' : 'failed'}`);
    } finally {
      clearTimeout(timer);
    }
  }
}
