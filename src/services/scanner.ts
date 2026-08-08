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
