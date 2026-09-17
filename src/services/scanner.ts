import { connect as tlsConnect } from 'node:tls';
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import { confirmXss, enumerateInjectionPoints, saveEvidence, type XssConfirmImpl } from './active-scanner.js';
import { discoverLinks } from './discovery.js';
import { findDisallowedAddress, isDisallowedAddress } from './ssrf-guard.js';
import {
  detectHeaderFindings,
  detectTlsFindings,
  extractVersionBanners,
  parsePassiveDocument,
  NO_TLS_FINDING,
  type HeaderFinding,
  type PassiveDocument,
  type TlsFinding,
  type TlsInfo,
  type VersionBanner,
} from './passive-checks.js';
import {
  scans,
  scanTargets,
  findings,
  type ScanTargetStatus,
  type FindingSeverity,
  type FindingConfidence,
  type ScanMode,
  type InjectionAttempt,
} from '../db/schema.js';

export { detectHeaderFindings, detectTlsFindings, extractVersionBanners, parsePassiveDocument, NO_TLS_FINDING };
export { isDisallowedAddress };
export type { HeaderFinding, PassiveDocument, TlsFinding, TlsInfo, VersionBanner };

// The passive header/body detector, injectable so a test can observe the parsed
// document that reaches the boundary. Defaults to detectHeaderFindings.
export type PassiveHeaderDetect = (
  headers: Record<string, string>,
  setCookies: string[],
  document: PassiveDocument | null,
  pageUrl: URL,
) => HeaderFinding[];

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

function lowercaseHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
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
  explanation?: string;
};

export type LlmEnrichment = { explanation: string; suggestedFix: string };
// The id is a synthetic per-call discriminator (f0, f1, ...), not stored anywhere —
// it exists so a short, reordered, or truncated LLM response can still be matched
// back to the finding it belongs to instead of relying on array position.
export type EnrichmentRequest = PendingFinding & { id: string };
export type LlmEnrichmentResult = LlmEnrichment & { id: string };
export type LlmEnrichImpl = (findingsToEnrich: EnrichmentRequest[]) => Promise<LlmEnrichmentResult[]>;

// Mirrors defaultOsvCheck's approach: a raw call against the provider's HTTP API
// rather than pulling in `@anthropic-ai/sdk` as a dependency, keeping runtime deps
// minimal per the coding-standards skill. Structured tool-use asks the model to
// return one { id, explanation, suggestedFix } tuple per finding it can address;
// a short or reordered response is matched back to findings by id, not position.
async function defaultLlmEnrich(findingsToEnrich: EnrichmentRequest[]): Promise<LlmEnrichmentResult[]> {
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
            'Submit a plain-English explanation and suggested fix for each finding, echoing back the id given for each one.',
          input_schema: {
            type: 'object',
            properties: {
              enrichments: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    explanation: { type: 'string' },
                    suggestedFix: { type: 'string' },
                  },
                  required: ['id', 'explanation', 'suggestedFix'],
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
          content: `Explain each of these security scan findings in plain English and suggest a fix. Echo back each finding's "id" in your response. Findings: ${JSON.stringify(findingsToEnrich)}`,
        },
      ],
    }),
  });
  if (!response.ok) throw new Error(`Anthropic API call failed with status ${response.status}`);

  const data = (await response.json()) as {
    content?: { type: string; input?: { enrichments?: LlmEnrichmentResult[] } }[];
  };
  const toolUse = data.content?.find((block) => block.type === 'tool_use');
  const enrichments = toolUse?.input?.enrichments;
  if (enrichments === undefined) throw new Error('Anthropic API did not return structured enrichment output');

  return enrichments;
}

// Same-origin discovery bounds, per the roadmap: depth-2, 25 discovered pages per
// operator-submitted root, regardless of how much depth remains.
// One bounding mechanism, two uses: a per-target allowance for extra HTTP requests
// (robots.txt and the exposed-file probes) and the per-root cap on discovered pages.
// They bound different resources and so hold different limits, but issue 022 asked
// for a single helper rather than a second hand-rolled counter, and 014's inline
// counter is retrofitted onto it here.
class Budget {
  #remaining: number;

  constructor(limit: number) {
    this.#remaining = limit;
  }

  // Returns false once exhausted; callers skip the work rather than throwing.
  tryConsume(): boolean {
    if (this.#remaining <= 0) return false;
    this.#remaining -= 1;
    return true;
  }
}

// Bounds how many wrapped tasks run at once. Used to cap concurrent browser contexts
// during active scanning independently of the target batch size: passive work on the
// same scan keeps running at full width while at most `limit` confirmations are live.
class Semaphore {
  #available: number;
  readonly #waiters: (() => void)[] = [];

  constructor(limit: number) {
    this.#available = limit;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#available > 0) {
      this.#available -= 1;
    } else {
      await new Promise<void>((resolve) => this.#waiters.push(resolve));
    }
    try {
      return await task();
    } finally {
      const next = this.#waiters.shift();
      if (next !== undefined) next();
      else this.#available += 1;
    }
  }
}

// Probing is bounded by content shape, not just status: a site that answers every
// unknown path with a 200 SPA shell would otherwise report an exposed .env on every
// target. Each probe therefore names what the real file looks like. `/server-status`
// and `security.txt` carry shape tests too, which the issue's table did not require,
// because that same SPA shell would otherwise trip them.
const EXPOSED_FILE_PROBES: {
  path: string;
  category: string;
  severity: FindingSeverity;
  matches: (body: string) => boolean;
  explanation: string;
}[] = [
  {
    path: '/.git/HEAD',
    category: 'exposed-git-directory',
    severity: 'critical',
    matches: (body) => /^ref:\s/.test(body.trimStart()),
    explanation: 'A .git directory is served, exposing the repository and its history.',
  },
  {
    path: '/.env',
    category: 'exposed-env-file',
    severity: 'critical',
    matches: (body) => /^[A-Z_][A-Z0-9_]*=/m.test(body),
    explanation: 'A .env file is served, typically exposing credentials and secrets.',
  },
  {
    path: '/server-status',
    category: 'exposed-server-status',
    severity: 'medium',
    matches: (body) => /server status/i.test(body),
    explanation: 'The Apache server-status page is publicly reachable, revealing live request data.',
  },
  {
    path: '/.well-known/security.txt',
    category: 'security-txt-present',
    severity: 'info',
    // Contact is the one mandatory field in RFC 9116.
    matches: (body) => /^contact:/im.test(body),
    explanation: 'A security.txt is published, giving researchers a documented disclosure route.',
  },
];

const MAX_DISCOVERY_DEPTH = 2;
const MAX_DISCOVERED_PER_ROOT = 25;

// Discovery only parses HTML, and #concurrency of these bodies sit in memory at
// once, so a body is read only when the server says it is HTML, and only up to
// MAX_HTML_BYTES — a 500 MB octet-stream target is never buffered. A read that
// fails mid-stream (socket dropped) degrades to "no links found"; that catch is
// deliberately around the stream read alone, so a programming error elsewhere —
// e.g. reading a body something upstream already consumed — still surfaces
// instead of silently turning discovery off.
const MAX_HTML_BYTES = 2 * 1024 * 1024;

async function readHtmlBody(response: Response): Promise<string> {
  const contentType = response.headers.get('content-type') ?? '';
  if (!/^\s*(text\/html|application\/xhtml\+xml)\b/i.test(contentType)) return '';

  const body = response.body;
  if (body === null) return '';

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let html = '';
  let bytes = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;

      bytes += value.byteLength;
      if (bytes > MAX_HTML_BYTES) {
        html += decoder.decode(value.subarray(0, value.byteLength - (bytes - MAX_HTML_BYTES)));
        break;
      }
      html += decoder.decode(value, { stream: true });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`body read failed: ${message}`);
  } finally {
    void reader.cancel().catch(() => {});
  }

  return html;
}

// Scoped to a single #runScan call, not the instance: discovery bookkeeping (depth,
// root, per-root count, and which URLs are already a target) only makes sense for the
// scan currently running, mirroring how cveCache/llmCache are scan-scoped.
type DiscoveryContext = {
  seenUrls: Set<string>;
  depthOf: Map<number, number>;
  rootOf: Map<number, number>;
  discoveredCount: Map<number, Budget>;
};

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
  readonly #maxExtraRequests: number;
  readonly #concurrency: number;
  readonly #defaultUserAgent: string;
  readonly #xssConfirmImpl: XssConfirmImpl;
  readonly #passiveHeaderDetect: PassiveHeaderDetect;
  // Caps concurrent browser contexts during active scanning, independent of the
  // target batch size — passive work continues at full width. See the Semaphore note.
  readonly #browserSemaphore: Semaphore;
  // Hostnames the SSRF guard is told to permit even though they resolve to a
  // disallowed (e.g. loopback) address. Empty in production and set only by tests
  // that serve a fixture on 127.0.0.1 — deliberately a constructor option, not an
  // env var, so nothing in production can accidentally disable the guard.
  readonly #allowedHosts: Set<string>;

  constructor(
    db: Db,
    options: {
      fetchImpl?: FetchImpl;
      tlsCheckImpl?: TlsCheckImpl;
      osvCheckImpl?: OsvCheckImpl;
      llmEnrichImpl?: LlmEnrichImpl;
      timeoutMs?: number;
      maxExtraRequests?: number;
      concurrency?: number;
      defaultUserAgent?: string;
      xssConfirmImpl?: XssConfirmImpl;
      browserConcurrency?: number;
      allowedHosts?: string[];
      passiveHeaderDetect?: PassiveHeaderDetect;
    } = {},
  ) {
    this.#db = db;
    this.#fetchImpl = options.fetchImpl ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    // Every request beyond a target's primary fetch draws on this: robots.txt plus
    // the four probes fit in the default with one to spare.
    this.#maxExtraRequests = options.maxExtraRequests ?? 6;
    this.#concurrency = options.concurrency ?? 10;
    this.#defaultUserAgent = options.defaultUserAgent ?? 'colossus-scanner/1.0';
    this.#xssConfirmImpl = options.xssConfirmImpl ?? confirmXss;
    this.#passiveHeaderDetect = options.passiveHeaderDetect ?? detectHeaderFindings;
    this.#browserSemaphore = new Semaphore(options.browserConcurrency ?? 2);
    this.#allowedHosts = new Set(options.allowedHosts ?? []);
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
    if (options.userAgent !== undefined && options.userAgent.trim() === '') {
      throw new ScanValidationError('userAgent must not be blank');
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

    void this.#runScan(scan.id, targetRows, scan.userAgent ?? this.#defaultUserAgent, scan.mode);

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

  async #runScan(scanId: number, targetRows: ScanTarget[], userAgent: string, mode: ScanMode): Promise<void> {
    this.#db.update(scans).set({ status: 'running' }).where(eq(scans.id, scanId)).run();

    // Cached per scan run, not on the instance: the PRD requires CVE lookups to be
    // cached per unique version string *within a scan* and never reused across scans.
    const cveCache = new Map<string, OsvMatch | null>();
    // Cached per scan run too: identical finding-sets within one scan share a single
    // LLM call, but explanations are never reused across scans (findings differ by
    // target and time even when the category/severity shape repeats).
    const llmCache = new Map<string, (LlmEnrichment | null)[]>();

    // Roots are the operator-submitted targets: depth 0, and their own discovery
    // budget. Discovery can add new rows to the queue mid-run, so this loop drains a
    // growing queue rather than iterating the fixed initial batch.
    const discovery: DiscoveryContext = {
      seenUrls: new Set(targetRows.map((t) => t.url)),
      depthOf: new Map(targetRows.map((t) => [t.id, 0])),
      rootOf: new Map(targetRows.map((t) => [t.id, t.id])),
      discoveredCount: new Map(targetRows.map((t) => [t.id, new Budget(MAX_DISCOVERED_PER_ROOT)])),
    };

    const queue = [...targetRows];
    while (queue.length > 0) {
      const batch = queue.splice(0, this.#concurrency);
      const discoveredBatches = await Promise.all(
        batch.map((target) => this.#processTarget(target, cveCache, llmCache, userAgent, mode, discovery)),
      );
      for (const discovered of discoveredBatches) queue.push(...discovered);
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
    userAgent: string,
    mode: ScanMode,
    discovery: DiscoveryContext,
  ): Promise<ScanTarget[]> {
    console.warn(`[scan ${target.scanId}] ${target.url} started`);

    const targetUrl = new URL(target.url);
    const hostname = targetUrl.hostname;
    const disallowedAddress = this.#allowedHosts.has(hostname) ? null : await findDisallowedAddress(hostname);
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
      return [];
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const start = performance.now();

    try {
      const response = await this.#fetchImpl(target.url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': userAgent },
      });
      const elapsed = Math.round(performance.now() - start);
      const status: ScanTargetStatus = 'ok';
      const redirectLocation = response.headers.get('location');
      const responseHeaders = lowercaseHeaders(response.headers);
      const setCookies = response.headers.getSetCookie();

      // Read the body here, immediately after the fetch and while the abort timer
      // still bounds it. Discovery is the last step of the pipeline, so deferring
      // the read until then would let a throw from any intervening step (TLS, CVE,
      // enrichment, active-mode injection) silently skip discovery.
      const html = await readHtmlBody(response);
      // Parse the (bounded) body once here so every body-derived consumer works off a
      // single parsed document rather than re-parsing the hostile string. An empty
      // string — non-HTML content type, no body, or a read that failed mid-stream —
      // yields a null document, and body-derived checks are simply skipped.
      const document: PassiveDocument | null = html === '' ? null : parsePassiveDocument(html);

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

      const pendingFindings: PendingFinding[] = [
        ...this.#passiveHeaderDetect(responseHeaders, setCookies, document, targetUrl),
      ];

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

      const requestBudget = new Budget(this.#maxExtraRequests);
      const robotsBody = await this.#fetchRobotsTxt(targetUrl, userAgent, requestBudget);
      pendingFindings.push(...(await this.#probeExposedFiles(targetUrl, userAgent, requestBudget)));
      for (const banner of extractVersionBanners(responseHeaders, robotsBody, document)) {
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
            explanation: finding.explanation ?? enrichment?.explanation ?? null,
            suggestedFix: enrichment?.suggestedFix ?? null,
          })
          .run();
      }

      if (mode === 'active') {
        await this.#injectQueryParams(target, targetUrl, userAgent);
      }

      // Discovery runs regardless of mode — it's non-intrusive HTML parsing, not a
      // payload-sending check, so it isn't gated behind the active-mode attestation.
      const discovered = this.#discoverTargets(target, targetUrl, html, robotsBody, discovery);

      console.warn(`[scan ${target.scanId}] ${target.url} succeeded`);
      return discovered;
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
      return [];
    } finally {
      clearTimeout(timer);
    }
  }

  // A discovered link becomes a real `scan_targets` row, run through the identical
  // pipeline as a submitted URL, bounded to depth-2 and 25 discovered pages per
  // operator-submitted root (walking `discoveredFrom` back to the root would also
  // work but requires a DB round-trip per target; the in-memory maps are scoped to
  // one #runScan call and cost nothing extra).
  #discoverTargets(
    target: ScanTarget,
    targetUrl: URL,
    html: string,
    robotsTxt: string | null,
    discovery: DiscoveryContext,
  ): ScanTarget[] {
    const depth = discovery.depthOf.get(target.id) ?? 0;
    if (depth >= MAX_DISCOVERY_DEPTH) return [];

    const rootId = discovery.rootOf.get(target.id) ?? target.id;
    const links = discoverLinks({ url: targetUrl, html }, robotsTxt);
    const rows: (typeof scanTargets.$inferInsert)[] = [];

    for (const url of links) {
      if (discovery.seenUrls.has(url)) continue;

      // Breaking here leaves the rest of this page's links out of `seenUrls`, so a
      // sibling page under another root can still reach them — intended: the cap is
      // per root, not a global "never visit this URL again".
      if (discovery.discoveredCount.get(rootId)?.tryConsume() !== true) break;

      discovery.seenUrls.add(url);
      rows.push({ scanId: target.scanId, url, status: 'pending', discoveredFrom: target.id });
    }

    if (rows.length === 0) return [];

    // One insert for the whole page rather than one per link: up to 25 round-trips
    // per page otherwise, and #concurrency pages are in flight at once.
    const created = this.#db.insert(scanTargets).values(rows).returning().all();
    if (created.length !== rows.length) throw new Error('failed to insert discovered scan targets');

    for (const row of created) {
      discovery.depthOf.set(row.id, depth + 1);
      discovery.rootOf.set(row.id, rootId);
    }

    return created;
  }

  // Active-mode only: for each query parameter, substitute a unique canary payload,
  // fetch the mutated URL, then load it in a headless browser to see whether the
  // marker executes. Each attempt records its confirmation outcome so a
  // `not_vulnerable` (page escaped it) is visibly distinct from an `unavailable`
  // (we couldn't test it); a `confirmed` outcome also writes a definitive `xss`
  // finding. A target with no query parameters produces zero attempts. The mutated
  // URLs share the target's host, which the SSRF guard already cleared;
  // per-navigation redirect guarding is 012.
  async #injectQueryParams(target: ScanTarget, targetUrl: URL, userAgent: string): Promise<void> {
    const points = enumerateInjectionPoints(targetUrl);
    if (points.length === 0) return;

    const attempts: InjectionAttempt[] = [];
    for (const point of points) {
      try {
        await this.#fetchImpl(point.url, { redirect: 'manual', headers: { 'user-agent': userAgent } });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.warn(`[scan ${target.scanId}] ${point.url} injection fetch failed: ${message}`);
      }

      const result = await this.#browserSemaphore.run(() => this.#xssConfirmImpl(point.url, point.payload));
      attempts.push({ injectionPoint: point.injectionPoint, payload: point.payload, ...result });

      if (result.outcome === 'confirmed') {
        const [inserted] = this.#db
          .insert(findings)
          .values({
            scanTargetId: target.id,
            category: 'xss',
            severity: 'high',
            confidence: 'definitive',
            injectionPoint: point.injectionPoint,
            payload: point.payload,
          })
          .returning({ id: findings.id })
          .all();

        // The evidence filename is the finding id, known only after the insert, so the
        // screenshot is written and linked here rather than at capture time.
        if (inserted !== undefined && result.screenshot !== undefined) {
          const evidencePath = await saveEvidence(target.scanId, inserted.id, result.screenshot);
          this.#db.update(findings).set({ evidencePath }).where(eq(findings.id, inserted.id)).run();
        }
      }
    }

    this.#db.update(scanTargets).set({ injectionAttempts: attempts }).where(eq(scanTargets.id, target.id)).run();
  }

  async #fetchRobotsTxt(targetUrl: URL, userAgent: string, budget: Budget): Promise<string | null> {
    if (!budget.tryConsume()) return null;
    try {
      const robotsUrl = new URL('/robots.txt', targetUrl).toString();
      const response = await this.#fetchImpl(robotsUrl, { redirect: 'manual', headers: { 'user-agent': userAgent } });
      return await response.text();
    } catch {
      // robots.txt is an extra probe surface, not a required one — a missing or
      // broken robots.txt just means banner extraction relies on headers alone.
      return null;
    }
  }

  // Same-origin GETs for ordinary paths: no payload, so this runs in passive mode and
  // needs no attestation. The host has already cleared the SSRF guard in #processTarget
  // and every probe URL is built against it, so no probe can reach a different host.
  async #probeExposedFiles(targetUrl: URL, userAgent: string, budget: Budget): Promise<PendingFinding[]> {
    const result: PendingFinding[] = [];

    for (const probe of EXPOSED_FILE_PROBES) {
      if (!budget.tryConsume()) break;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
      try {
        const url = new URL(probe.path, targetUrl).toString();
        const response = await this.#fetchImpl(url, {
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'user-agent': userAgent },
        });
        if (response.status !== 200) continue;
        if (!probe.matches(await response.text())) continue;

        result.push({
          category: probe.category,
          severity: probe.severity,
          confidence: 'definitive',
          explanation: probe.explanation,
        });
      } catch {
        // A probe is best-effort: an unreachable or slow path says nothing about the
        // target's primary status, so it must not fail the target.
      } finally {
        clearTimeout(timer);
      }
    }

    return result;
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

    const requests: EnrichmentRequest[] = findingsToEnrich.map((finding, i) => ({
      ...finding,
      id: `f${i}`,
    }));

    let byId = new Map<string, LlmEnrichmentResult>();
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const enrichments = await this.#llmEnrichImpl(requests);
        byId = new Map(enrichments.map((e) => [e.id, e]));
        break;
      } catch (err) {
        if (attempt === 2) {
          const message = err instanceof Error ? err.message : String(err);
          console.warn(`[scan ${scanId}] ${url} LLM enrichment failed after retry: ${message}`);
        }
      }
    }

    // Matched by synthetic id, not array position: a short, reordered, or truncated
    // response leaves the unmatched findings null instead of misattributing another
    // finding's explanation/suggestedFix to them.
    const result: (LlmEnrichment | null)[] = requests.map((request) => {
      const match = byId.get(request.id);
      return match !== undefined ? { explanation: match.explanation, suggestedFix: match.suggestedFix } : null;
    });

    cache.set(key, result);
    return result;
  }
}
