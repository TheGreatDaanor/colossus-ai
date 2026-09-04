import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import Anthropic from '@anthropic-ai/sdk';
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import {
  scans,
  scanTargets,
  findings,
  type ScanTargetStatus,
  type FindingSeverity,
  type FindingConfidence,
  type ScanMode,
} from '../db/schema.js';
import { enumerateInjectionAttempts } from './active-scanner.js';

export class ScanValidationError extends Error {}

const MAX_URLS = 100;

export type Scan = typeof scans.$inferSelect;
export type ScanTarget = typeof scanTargets.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type ScanWithTargets = Scan & { targets: (ScanTarget & { findings: Finding[] })[] };

export type StartScanOptions = {
  name?: string;
  userAgent?: string;
  mode?: ScanMode;
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

export type EnrichedFinding = { category: string; explanation: string; suggestedFix: string };
export type EnrichImpl = (findings: Finding[]) => Promise<EnrichedFinding[]>;

const ENRICH_MODEL = 'claude-opus-5';

const ENRICH_TOOL = {
  name: 'report_finding_explanations',
  description: 'Report a plain-English explanation and suggested fix for each security finding.',
  input_schema: {
    type: 'object' as const,
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            category: { type: 'string', description: 'The finding category being explained.' },
            explanation: { type: 'string', description: 'Why this finding matters, in plain English.' },
            suggested_fix: { type: 'string', description: 'A concrete, actionable remediation step.' },
          },
          required: ['category', 'explanation', 'suggested_fix'],
          additionalProperties: false,
        },
      },
    },
    required: ['findings'],
    additionalProperties: false,
  },
  strict: true,
};

// Scanned sites control some of the text that reaches this prompt (banners, cookie names).
// Prompt-injection hardening is explicitly out of scope per the PRD — raw findings are always
// rendered regardless of what comes back here, so a hijacked explanation cannot hide a finding.
async function defaultEnrich(findingRows: Finding[]): Promise<EnrichedFinding[]> {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();

  const response = await client.messages.create({
    model: ENRICH_MODEL,
    max_tokens: 16000,
    thinking: { type: 'adaptive' },
    tools: [ENRICH_TOOL],
    tool_choice: { type: 'tool', name: ENRICH_TOOL.name },
    messages: [
      {
        role: 'user',
        content:
          'Explain each of these web security scan findings for the site owner, and suggest a fix. ' +
          'Return exactly one entry per input category, reusing the category string verbatim.\n\n' +
          JSON.stringify(
            findingRows.map((f) => ({
              category: f.category,
              severity: f.severity,
              confidence: f.confidence,
              cve_id: f.cveId,
            })),
          ),
      },
    ],
  });

  const toolUse = response.content.find((block) => block.type === 'tool_use');
  if (toolUse === undefined) throw new Error('enrichment response contained no tool_use block');

  const { findings: entries } = toolUse.input as {
    findings: { category: string; explanation: string; suggested_fix: string }[];
  };
  return entries.map((e) => ({
    category: e.category,
    explanation: e.explanation,
    suggestedFix: e.suggested_fix,
  }));
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

const CVE_FINDING_CATEGORY = 'known-vulnerability';
// A version-string match doesn't prove a fix wasn't backported, so CVE findings stay
// `possible` confidence (per the PRD) rather than `definitive`. Severity isn't reported
// by a bare OSV.dev match in this v1 integration, so every match is treated as `high` —
// a known, matched CVE is a serious signal even without a parsed CVSS score.
const CVE_FINDING_SEVERITY: FindingSeverity = 'high';

export type LlmEnrichInput = {
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  cveId: string | null;
};
export type LlmEnrichment = { explanation: string; suggestedFix: string };
export type EnrichedFinding = { explanation: string | null; suggestedFix: string | null };
export type LlmEnrichImpl = (findings: LlmEnrichInput[]) => Promise<LlmEnrichment[]>;

const ENRICHMENT_TOOL_NAME = 'report_finding_explanations';
const LLM_RETRY_DELAY_MS = 1000;

async function defaultLlmEnrich(findings: LlmEnrichInput[]): Promise<LlmEnrichment[]> {
  const client = new Anthropic();
  const response = await client.messages.create({
    model: 'claude-sonnet-5',
    max_tokens: 4096,
    tool_choice: { type: 'tool', name: ENRICHMENT_TOOL_NAME },
    tools: [
      {
        name: ENRICHMENT_TOOL_NAME,
        description:
          'Report a plain-English explanation and a suggested fix for each security finding, one entry per finding, in the same order as the input list.',
        input_schema: {
          type: 'object',
          properties: {
            findings: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  explanation: { type: 'string', description: 'Plain-English explanation of the risk.' },
                  suggestedFix: { type: 'string', description: 'A concrete suggested fix.' },
                },
                required: ['explanation', 'suggestedFix'],
              },
            },
          },
          required: ['findings'],
        },
      },
    ],
    messages: [
      {
        role: 'user',
        content: `For each of these security findings, give a short plain-English explanation and a suggested fix. Findings:\n${JSON.stringify(findings)}`,
      },
    ],
  });

  const toolUse = response.content.find((block) => block.type === 'tool_use');
  if (toolUse === undefined || toolUse.type !== 'tool_use') {
    throw new Error('LLM enrichment response did not include a tool_use block');
  }

  const input = toolUse.input as { findings?: unknown };
  if (!Array.isArray(input.findings)) throw new Error('LLM enrichment response is missing a findings array');
  return input.findings as LlmEnrichment[];
}

function findingFingerprint(finding: LlmEnrichInput): string {
  return `${finding.category}|${finding.severity}|${finding.confidence}|${finding.cveId ?? ''}`;
}

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
      throw new ScanValidationError('mode "active" requires confirmAuthorized: true');
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
        mode: options.mode ?? 'passive',
        confirmAuthorized: options.confirmAuthorized ?? null,
        authorizationNote: options.authorizationNote ?? null,
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

    void this.#runScan(scan.id, scan.mode, targetRows);

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

  async #runScan(scanId: number, mode: ScanMode, targetRows: ScanTarget[]): Promise<void> {
    this.#db.update(scans).set({ status: 'running' }).where(eq(scans.id, scanId)).run();

    // Cached per scan run, not on the instance: the PRD requires CVE lookups to be
    // cached per unique version string *within a scan* and never reused across scans.
    const cveCache = new Map<string, OsvMatch | null>();
    // Same rationale, for LLM enrichment: identical finding-sets within one scan
    // reuse a single call, keyed by a fingerprint of the sorted finding-set.
    const llmCache = new Map<string, Promise<EnrichedFinding[]>>();

    // Same per-scan (never cross-scan) rule as cveCache: keyed on the finding *set*, since
    // that set is the entire input to the LLM call — two targets with the same findings get
    // the same explanations, so the second one costs nothing. Holds the in-flight promise so
    // targets running concurrently in the same batch share one call rather than racing.
    const enrichCache = new Map<string, Promise<EnrichedFinding[] | null>>();

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
    llmCache: Map<string, Promise<EnrichedFinding[]>>,
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
      const injectionAttempts = mode === 'active' ? enumerateInjectionAttempts(target.url) : undefined;

      this.#db
        .update(scanTargets)
        .set({
          status,
          statusCode: response.status,
          responseHeaders,
          responseTimeMs: elapsed,
          redirectLocation: redirectLocation ?? null,
          ...(injectionAttempts !== undefined ? { injectionAttempts } : {}),
        })
        .where(eq(scanTargets.id, target.id))
        .run();

      // Findings are collected here rather than inserted immediately so that
      // #enrichFindings sees the target's whole finding-set at once — the LLM
      // dedup cache is keyed on the full set, not per-individual-finding.
      const targetFindings: LlmEnrichInput[] = [];

      for (const finding of detectHeaderFindings(responseHeaders)) {
        targetFindings.push({ ...finding, cveId: null });
      }

      if (targetUrl.protocol === 'http:') {
        targetFindings.push({ ...NO_TLS_FINDING, cveId: null });
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

          for (const finding of detectTlsFindings(tlsInfo)) {
            targetFindings.push({ ...finding, cveId: null });
          }
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
          targetFindings.push({
            category: CVE_FINDING_CATEGORY,
            severity: CVE_FINDING_SEVERITY,
            confidence: 'possible',
            cveId: match.cveId,
          });
        }
      }

      const enrichments = await this.#enrichFindings(targetFindings, llmCache, target.scanId, target.url);
      targetFindings.forEach((finding, index) => {
        const enrichment = enrichments[index] ?? { explanation: null, suggestedFix: null };
        this.#db
          .insert(findings)
          .values({ scanTargetId: target.id, ...finding, ...enrichment })
          .run();
      });

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
    targetFindings: LlmEnrichInput[],
    cache: Map<string, Promise<EnrichedFinding[]>>,
    scanId: number,
    url: string,
  ): Promise<EnrichedFinding[]> {
    if (targetFindings.length === 0) return [];

    // Sorted by fingerprint so two targets with the same findings in a different
    // insertion order still hit the cache under the same key.
    const withIndex = targetFindings.map((finding, index) => ({ finding, index }));
    const sorted = [...withIndex].sort((a, b) =>
      findingFingerprint(a.finding).localeCompare(findingFingerprint(b.finding)),
    );
    const key = sorted.map(({ finding }) => findingFingerprint(finding)).join('|');

    // The promise itself (not its resolved value) is cached synchronously,
    // before any await — so a second target reaching this key while the first
    // call is still in flight awaits the same promise instead of firing its
    // own concurrent LLM call.
    let inFlight = cache.get(key);
    if (!inFlight) {
      inFlight = (async () => {
        for (let attempt = 1; attempt <= 2; attempt++) {
          try {
            const result = await this.#llmEnrichImpl(sorted.map(({ finding }) => finding));
            if (result.length !== sorted.length) throw new Error('LLM enrichment returned a mismatched result count');
            return result;
          } catch (err) {
            if (attempt === 2) {
              const message = err instanceof Error ? err.message : String(err);
              console.warn(`[scan ${scanId}] ${url} LLM enrichment failed after retry: ${message}`);
            } else {
              await new Promise((resolve) => setTimeout(resolve, LLM_RETRY_DELAY_MS));
            }
          }
        }
        return sorted.map(() => ({ explanation: null, suggestedFix: null }));
      })();
      cache.set(key, inFlight);
    }

    const sortedResult = await inFlight;

    const result: EnrichedFinding[] = targetFindings.map(() => ({ explanation: null, suggestedFix: null }));
    sorted.forEach(({ index }, position) => {
      const enriched = sortedResult[position];
      if (enriched) result[index] = enriched;
    });
    return result;
  }
}
