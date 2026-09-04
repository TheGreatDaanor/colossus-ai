import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import {
  scans,
  scanTargets,
  findings,
  type ScanTargetStatus,
  type FindingSeverity,
  type FindingConfidence,
} from '../db/schema.js';

export class ScanValidationError extends Error {}

const MAX_URLS = 100;

export type Scan = typeof scans.$inferSelect;
export type ScanTarget = typeof scanTargets.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type ScanWithTargets = Scan & {
  targets: (ScanTarget & { findings: Finding[] })[];
  findingsBySeverity: Record<FindingSeverity, number>;
};

export type StartScanOptions = {
  name?: string;
  userAgent?: string;
  mode?: 'passive' | 'active';
  confirmAuthorized?: boolean;
  authorizationNote?: string;
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

export type HeaderFinding = {
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
};

// Severity is not pinned by the PRD beyond the five-value scale, so this is a
// judgment call: missing HSTS/CSP allow the broadest attacks (no encryption
// enforcement / arbitrary script injection) so they skew high; framing and
// MIME-sniffing protections are narrower in impact, so they sit lower.
const MISSING_HEADER_FINDINGS: { header: string; category: string; severity: FindingSeverity }[] = [
  { header: 'content-security-policy', category: 'missing-csp', severity: 'high' },
  { header: 'strict-transport-security', category: 'missing-hsts', severity: 'high' },
  { header: 'x-frame-options', category: 'missing-x-frame-options', severity: 'medium' },
  { header: 'x-content-type-options', category: 'missing-x-content-type-options', severity: 'low' },
  { header: 'referrer-policy', category: 'missing-referrer-policy', severity: 'low' },
  { header: 'permissions-policy', category: 'missing-permissions-policy', severity: 'low' },
];

function isCookieSecure(setCookie: string): boolean {
  const attributes = setCookie.split(';').map((part) => part.trim().toLowerCase());
  const hasSecure = attributes.includes('secure');
  const hasHttpOnly = attributes.includes('httponly');
  const hasSameSite = attributes.some((attr) => attr.startsWith('samesite='));
  return hasSecure && hasHttpOnly && hasSameSite;
}

export function detectHeaderFindings(headers: Record<string, string>): HeaderFinding[] {
  const result: HeaderFinding[] = MISSING_HEADER_FINDINGS.filter(({ header }) => !(header in headers)).map(
    ({ category, severity }) => ({ category, severity, confidence: 'definitive' }),
  );

  const setCookie = headers['set-cookie'];
  if (setCookie !== undefined && !isCookieSecure(setCookie)) {
    result.push({ category: 'insecure-cookie', severity: 'medium', confidence: 'definitive' });
  }

  return result;
}

export type TlsInfo = { version: string; certExpiresAt: Date };
export type TlsFinding = { category: string; severity: FindingSeverity; confidence: FindingConfidence };

const OUTDATED_TLS_VERSIONS = new Set(['TLSv1', 'TLSv1.1']);
const CERT_EXPIRY_WARNING_DAYS = 30;
const MS_PER_DAY = 1000 * 60 * 60 * 24;

export const NO_TLS_FINDING: TlsFinding = { category: 'no-tls', severity: 'high', confidence: 'definitive' };

export function detectTlsFindings(info: TlsInfo, now: Date = new Date()): TlsFinding[] {
  const result: TlsFinding[] = [];

  if (OUTDATED_TLS_VERSIONS.has(info.version)) {
    result.push({ category: 'outdated-tls', severity: 'high', confidence: 'definitive' });
  }

  const daysUntilExpiry = (info.certExpiresAt.getTime() - now.getTime()) / MS_PER_DAY;
  if (daysUntilExpiry <= CERT_EXPIRY_WARNING_DAYS) {
    result.push({ category: 'cert-expiring-soon', severity: 'medium', confidence: 'definitive' });
  }

  return result;
}

// Module-private: the only caller is `getScan`, and it is covered through that
// public seam rather than directly.
function summarizeFindingsBySeverity(rows: { severity: FindingSeverity }[]): Record<FindingSeverity, number> {
  const summary: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of rows) {
    // `severity` is a compile-time cast over a plain text column, so a row can carry
    // a value outside the union. `hasOwn`, not `in`: `in` walks the prototype chain,
    // so a severity of `constructor` or `toString` would slip past and corrupt the block.
    if (Object.hasOwn(summary, row.severity)) summary[row.severity] += 1;
  }
  return summary;
}

export type VersionBanner = { software: string; version: string };

// Neither the PRD nor the issue pins an exact banner source, so this is a judgment
// call: `name/version` is the de-facto convention for both the Server and
// X-Powered-By headers (e.g. `nginx/1.18.0`, `PHP/7.4.3`), and some software repeats
// that same convention in a robots.txt comment. Headers are checked first since
// they're the more reliable signal; robots.txt is only consulted if neither matches.
const BANNER_HEADER_NAMES = ['server', 'x-powered-by'];
const BANNER_PATTERN = /([A-Za-z][\w.-]*)\/(\d[\w.-]*)/;

export function extractVersionBanner(
  headers: Record<string, string>,
  robotsBody: string | null,
): VersionBanner | null {
  for (const headerName of BANNER_HEADER_NAMES) {
    const value = headers[headerName];
    if (value === undefined) continue;
    const match = BANNER_PATTERN.exec(value);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  if (robotsBody !== null) {
    const match = BANNER_PATTERN.exec(robotsBody);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  return null;
}

export type TlsCheckImpl = (hostname: string, port: number) => Promise<TlsInfo>;

function defaultTlsCheck(hostname: string, port: number, timeoutMs: number): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: hostname, port, servername: hostname, timeout: timeoutMs }, () => {
      const version = socket.getProtocol();
      const cert = socket.getPeerCertificate();
      socket.end();

      if (version === null || !cert.valid_to) {
        reject(new Error(`unable to read TLS info for ${hostname}:${port}`));
        return;
      }
      resolve({ version, certExpiresAt: new Date(cert.valid_to) });
    });

    socket.on('error', reject);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`TLS handshake to ${hostname}:${port} timed out`));
    });
  });
}

export type FetchImpl = (url: string, init: RequestInit) => Promise<Response>;

export type OsvMatch = { cveId: string };
export type OsvCheckImpl = (banner: VersionBanner) => Promise<OsvMatch | null>;

async function defaultOsvCheck(banner: VersionBanner): Promise<OsvMatch | null> {
  const response = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    body: JSON.stringify({ version: banner.version, package: { name: banner.software, ecosystem: 'Generic' } }),
  });
  if (!response.ok) throw new Error(`OSV.dev query failed with status ${response.status}`);

  const data = (await response.json()) as { vulns?: { id: string }[] };
  const first = data.vulns?.[0];
  return first !== undefined ? { cveId: first.id } : null;
}

export type PendingFinding = {
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  cveId?: string;
};

export type LlmEnrichment = { explanation: string; suggestedFix: string };
export type LlmEnrichImpl = (findingsToEnrich: PendingFinding[]) => Promise<LlmEnrichment[]>;

// Mirrors defaultOsvCheck's approach: a raw call against the provider's HTTP API
// rather than pulling in `@anthropic-ai/sdk` as a dependency, keeping runtime deps
// minimal per the coding-standards skill. Structured tool-use forces the model to
// return exactly one { explanation, suggestedFix } pair per finding, in order.
async function defaultLlmEnrich(findingsToEnrich: PendingFinding[]): Promise<LlmEnrichment[]> {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY ?? '',
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-5',
      max_tokens: 1024,
      tools: [
        {
          name: 'submit_finding_enrichment',
          description:
            'Submit a plain-English explanation and suggested fix for each finding, in the same order given.',
          input_schema: {
            type: 'object',
            properties: {
              enrichments: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    explanation: { type: 'string' },
                    suggestedFix: { type: 'string' },
                  },
                  required: ['explanation', 'suggestedFix'],
                },
              },
            },
            required: ['enrichments'],
          },
        },
      ],
      tool_choice: { type: 'tool', name: 'submit_finding_enrichment' },
      messages: [
        {
          role: 'user',
          content: `Explain each of these security scan findings in plain English and suggest a fix. Findings: ${JSON.stringify(findingsToEnrich)}`,
        },
      ],
    }),
  });
  if (!response.ok) throw new Error(`Anthropic API call failed with status ${response.status}`);

  const data = (await response.json()) as {
    content?: { type: string; input?: { enrichments?: LlmEnrichment[] } }[];
  };
  const toolUse = data.content?.find((block) => block.type === 'tool_use');
  const enrichments = toolUse?.input?.enrichments;
  if (enrichments === undefined) throw new Error('Anthropic API did not return structured enrichment output');

  return enrichments;
}

const CVE_FINDING_CATEGORY = 'known-vulnerability';
// A version-string match doesn't prove a fix wasn't backported, so CVE findings stay
// `possible` confidence (per the PRD) rather than `definitive`. Severity isn't reported
// by a bare OSV.dev match in this v1 integration, so every match is treated as `high` —
// a known, matched CVE is a serious signal even without a parsed CVSS score.
const CVE_FINDING_SEVERITY: FindingSeverity = 'high';

export class ScannerService {
  readonly #db: Db;
  readonly #fetchImpl: FetchImpl;
  readonly #tlsCheckImpl: TlsCheckImpl;
  readonly #osvCheckImpl: OsvCheckImpl;
  readonly #llmEnrichImpl: LlmEnrichImpl;
  readonly #timeoutMs: number;
  readonly #concurrency: number;

  constructor(
    db: Db,
    options: {
      fetchImpl?: FetchImpl;
      tlsCheckImpl?: TlsCheckImpl;
      osvCheckImpl?: OsvCheckImpl;
      llmEnrichImpl?: LlmEnrichImpl;
      timeoutMs?: number;
      concurrency?: number;
    } = {},
  ) {
    this.#db = db;
    this.#fetchImpl = options.fetchImpl ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#concurrency = options.concurrency ?? 10;
    this.#tlsCheckImpl =
      options.tlsCheckImpl ?? ((hostname, port) => defaultTlsCheck(hostname, port, this.#timeoutMs));
    this.#osvCheckImpl = options.osvCheckImpl ?? defaultOsvCheck;
    this.#llmEnrichImpl = options.llmEnrichImpl ?? defaultLlmEnrich;
  }

  async startScan(urls: string[], options: StartScanOptions = {}): Promise<Scan> {
    if (urls.length === 0) throw new ScanValidationError('urls must not be empty');
    if (urls.length > MAX_URLS) throw new ScanValidationError(`urls must not exceed ${MAX_URLS}`);
    if (options.mode === 'active' && options.confirmAuthorized !== true) {
      throw new ScanValidationError('mode: "active" requires confirmAuthorized: true');
    }

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
        mode: options.mode ?? 'passive',
        confirmAuthorized: options.confirmAuthorized ?? null,
        authorizationNote: options.authorizationNote ?? null,
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

    const allFindings = targets.flatMap((target) => target.findings);

    return { ...scan, targets, findingsBySeverity: summarizeFindingsBySeverity(allFindings) };
  }

  async listScans(): Promise<Scan[]> {
    return this.#db.select().from(scans).orderBy(scans.createdAt).all().reverse();
  }

  async #runScan(scanId: number, targetRows: ScanTarget[]): Promise<void> {
    this.#db.update(scans).set({ status: 'running' }).where(eq(scans.id, scanId)).run();

    // Cached per scan run, not on the instance: the PRD requires CVE lookups to be
    // cached per unique version string *within a scan* and never reused across scans.
    const cveCache = new Map<string, OsvMatch | null>();
    // Cached per scan run too: identical finding-sets within one scan share a single
    // LLM call, but explanations are never reused across scans (findings differ by
    // target and time even when the category/severity shape repeats).
    const llmCache = new Map<string, (LlmEnrichment | null)[]>();

    for (let i = 0; i < targetRows.length; i += this.#concurrency) {
      const batch = targetRows.slice(i, i + this.#concurrency);
      await Promise.all(batch.map((target) => this.#processTarget(target, cveCache, llmCache)));
    }

    this.#db
      .update(scans)
      .set({ status: 'completed', completedAt: new Date() })
      .where(eq(scans.id, scanId))
      .run();
  }

  async #processTarget(
    target: ScanTarget,
    cveCache: Map<string, OsvMatch | null>,
    llmCache: Map<string, (LlmEnrichment | null)[]>,
  ): Promise<void> {
    console.warn(`[scan ${target.scanId}] ${target.url} started`);

    const targetUrl = new URL(target.url);
    const hostname = targetUrl.hostname;
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
      const responseHeaders = lowercaseHeaders(response.headers);

      this.#db
        .update(scanTargets)
        .set({
          status,
          statusCode: response.status,
          responseHeaders,
          responseTimeMs: elapsed,
          redirectLocation: redirectLocation ?? null,
        })
        .where(eq(scanTargets.id, target.id))
        .run();

      const pendingFindings: PendingFinding[] = [...detectHeaderFindings(responseHeaders)];

      if (targetUrl.protocol === 'http:') {
        pendingFindings.push(NO_TLS_FINDING);
      } else {
        // TLS-check failures degrade gracefully (target stays `ok`, TLS columns/findings
        // are just skipped) rather than failing the target — mirrors the CVE-lookup
        // degrade-on-failure behavior planned for 005, and keeps one bad handshake from
        // aborting the whole concurrency batch via an unhandled rejection in #runScan.
        try {
          const port = targetUrl.port ? Number(targetUrl.port) : 443;
          const tlsInfo = await this.#tlsCheckImpl(hostname, port);

          this.#db
            .update(scanTargets)
            .set({ tlsVersion: tlsInfo.version, tlsCertExpiresAt: tlsInfo.certExpiresAt })
            .where(eq(scanTargets.id, target.id))
            .run();

          pendingFindings.push(...detectTlsFindings(tlsInfo));
        } catch (tlsErr) {
          const message = tlsErr instanceof Error ? tlsErr.message : String(tlsErr);
          console.warn(`[scan ${target.scanId}] ${target.url} TLS check failed: ${message}`);
        }
      }

      const robotsBody = await this.#fetchRobotsTxt(targetUrl);
      const banner = extractVersionBanner(responseHeaders, robotsBody);
      if (banner !== null) {
        const match = await this.#lookupCve(banner, cveCache, target.scanId, target.url);
        if (match !== null) {
          pendingFindings.push({
            category: CVE_FINDING_CATEGORY,
            severity: CVE_FINDING_SEVERITY,
            confidence: 'possible',
            cveId: match.cveId,
          });
        }
      }

      const enrichments =
        pendingFindings.length > 0
          ? await this.#enrichFindings(pendingFindings, llmCache, target.scanId, target.url)
          : [];

      for (let i = 0; i < pendingFindings.length; i++) {
        const finding = pendingFindings[i];
        if (finding === undefined) continue;
        const enrichment = enrichments[i] ?? null;
        this.#db
          .insert(findings)
          .values({
            scanTargetId: target.id,
            ...finding,
            explanation: enrichment?.explanation ?? null,
            suggestedFix: enrichment?.suggestedFix ?? null,
          })
          .run();
      }

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

  async #fetchRobotsTxt(targetUrl: URL): Promise<string | null> {
    try {
      const robotsUrl = new URL('/robots.txt', targetUrl).toString();
      const response = await this.#fetchImpl(robotsUrl, { redirect: 'manual' });
      return await response.text();
    } catch {
      // robots.txt is an extra probe surface, not a required one — a missing or
      // broken robots.txt just means banner extraction relies on headers alone.
      return null;
    }
  }

  async #lookupCve(
    banner: VersionBanner,
    cache: Map<string, OsvMatch | null>,
    scanId: number,
    url: string,
  ): Promise<OsvMatch | null> {
    const key = `${banner.software}/${banner.version}`;
    if (cache.has(key)) return cache.get(key) ?? null;

    let match: OsvMatch | null = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        match = await this.#osvCheckImpl(banner);
        break;
      } catch (err) {
        if (attempt === 2) {
          const message = err instanceof Error ? err.message : String(err);
          console.warn(`[scan ${scanId}] ${url} CVE lookup failed after retry: ${message}`);
        }
      }
    }

    cache.set(key, match);
    return match;
  }

  async #enrichFindings(
    findingsToEnrich: PendingFinding[],
    cache: Map<string, (LlmEnrichment | null)[]>,
    scanId: number,
    url: string,
  ): Promise<(LlmEnrichment | null)[]> {
    const key = JSON.stringify(
      findingsToEnrich.map((f) => ({
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        cveId: f.cveId ?? null,
      })),
    );
    const cached = cache.get(key);
    if (cached !== undefined) return cached;

    let result: (LlmEnrichment | null)[] = findingsToEnrich.map(() => null);
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        result = await this.#llmEnrichImpl(findingsToEnrich);
        break;
      } catch (err) {
        if (attempt === 2) {
          const message = err instanceof Error ? err.message : String(err);
          console.warn(`[scan ${scanId}] ${url} LLM enrichment failed after retry: ${message}`);
        }
      }
    }

    cache.set(key, result);
    return result;
  }
}
