import type { HostSource } from '../db/schema.js';
import { apexOf } from './programs.js';

// A host observed by some source, before anything is known about its scope. The
// scope decision belongs to programs.ts and is made when the host is recorded.
export type ObservedHost = { hostname: string; source: HostSource };

// The CT query narrowed to "give me the decoded JSON for this apex". Injected so
// every test stubs it and no test contacts the real crt.sh endpoint.
export type CtFetchImpl = (apex: string) => Promise<unknown>;

// Thrown when the source could not be queried. The caller decides what that
// means: a scan treats it as non-fatal and keeps the inventory it already has.
export class EnumerationError extends Error {}

export type EnumerationServiceOptions = {
  ctFetchImpl?: CtFetchImpl;
  userAgent?: string;
  cacheTtlMs?: number;
  maxCacheEntries?: number;
  now?: () => number;
};

const CRT_SH_ENDPOINT = 'https://crt.sh';

// crt.sh answers 404 to a request that names no client, so the query identifies
// itself. Overridden by SCANNER_USER_AGENT alongside the scanner's own agent.
const DEFAULT_USER_AGENT = 'colossus-scanner/1.0';

// Long enough that an on-demand run straight after a scheduled one reuses the
// answer, short enough that a certificate issued today still shows up today.
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

// One long-lived process enumerates many programs, and an entry is one apex's
// host list — so the cache is bounded by count, oldest evicted first, rather
// than left to grow for as long as the process lives.
const DEFAULT_MAX_CACHE_ENTRIES = 256;

// crt.sh is frequently slow and sometimes never answers at all. Without a bound
// an on-demand enumerate would hold its request open for as long as crt.sh
// leaves the socket open.
const DEFAULT_CT_TIMEOUT_MS = 30_000;

const WILDCARD_PREFIX = '*.';

function normaliseHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

// crt.sh packs every identity of a certificate into one newline-separated
// `name_value`, so one record routinely names a dozen hosts across domains.
function namesIn(record: unknown): string[] {
  if (typeof record !== 'object' || record === null) return [];
  const { name_value: nameValue } = record as { name_value?: unknown };
  if (typeof nameValue !== 'string') return [];
  return nameValue.split('\n');
}

// A wildcard certificate names the subtree, not a host that exists. Recording
// the root keeps the evidence without inventing a hostname nobody has seen;
// wildcard detection proper is a later issue.
function toHostname(rawName: string): string | null {
  const name = normaliseHostname(rawName);
  const hostname = name.startsWith(WILDCARD_PREFIX) ? name.slice(WILDCARD_PREFIX.length) : name;
  return hostname === '' ? null : hostname;
}

// Only the apex being enumerated was authorized. A certificate covering other
// domains is common and is not a licence to enumerate them.
function isUnderApex(hostname: string, apex: string): boolean {
  return hostname === apex || hostname.endsWith(`.${apex}`);
}

export type CtFetchOptions = { userAgent?: string; endpoint?: string; timeoutMs?: number };

// The real crt.sh query. Every failure — refused, timed out, non-2xx, or a body
// that is not JSON — leaves as an EnumerationError, because the caller's whole
// contract is that a source outage is non-fatal and recorded on the program.
export function createCtFetch(options: CtFetchOptions = {}): CtFetchImpl {
  const userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
  const endpoint = options.endpoint ?? CRT_SH_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_CT_TIMEOUT_MS;

  return async (apex) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`${endpoint}/?q=${encodeURIComponent(`%.${apex}`)}&output=json`, {
        headers: { 'user-agent': userAgent },
        signal: controller.signal,
      });
      if (!response.ok) throw new EnumerationError(`crt.sh: ${response.status} ${response.statusText}`);
      return await response.json();
    } catch (err) {
      throw err instanceof EnumerationError ? err : new EnumerationError(`crt.sh query failed: ${String(err)}`);
    } finally {
      clearTimeout(timer);
    }
  };
}

type CacheEntry = { hosts: ObservedHost[]; storedAt: number };

// All outbound I/O for finding hosts. Kept out of programs.ts so the scope rules
// stay a pure function with no network behind them.
export class EnumerationService {
  #ctFetchImpl: CtFetchImpl;
  #cacheTtlMs: number;
  #maxCacheEntries: number;
  #now: () => number;
  #cache = new Map<string, CacheEntry>();

  constructor(options: EnumerationServiceOptions = {}) {
    this.#ctFetchImpl = options.ctFetchImpl ?? createCtFetch({ userAgent: options.userAgent ?? DEFAULT_USER_AGENT });
    this.#cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.#maxCacheEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
    this.#now = options.now ?? Date.now;
  }

  // Hosts named by certificates issued for `apex`, deduplicated and sorted.
  // Throws EnumerationError when the source could not be reached; a malformed or
  // unexpected response is not an error, it simply names no hosts.
  async enumerate(apex: string): Promise<ObservedHost[]> {
    const normalisedApex = normaliseHostname(apex);
    const cached = this.#cache.get(normalisedApex);
    if (cached && this.#now() - cached.storedAt <= this.#cacheTtlMs) return cached.hosts;

    let payload: unknown;
    try {
      payload = await this.#ctFetchImpl(normalisedApex);
    } catch (err) {
      // Only a successful query is cached: a cached outage would keep the
      // operator from retrying for as long as the entry lived.
      throw err instanceof EnumerationError ? err : new EnumerationError(`crt.sh query failed: ${String(err)}`);
    }

    const hosts = collectHosts(payload, normalisedApex);
    this.#remember(normalisedApex, hosts);
    return hosts;
  }
  // A Map iterates in insertion order, so the first key is the oldest entry.
  #remember(apex: string, hosts: ObservedHost[]): void {
    this.#cache.delete(apex);
    this.#cache.set(apex, { hosts, storedAt: this.#now() });
    while (this.#cache.size > this.#maxCacheEntries) {
      const oldest = this.#cache.keys().next();
      if (oldest.done) break;
      this.#cache.delete(oldest.value);
    }
  }
}

function collectHosts(payload: unknown, apex: string): ObservedHost[] {
  if (!Array.isArray(payload)) return [];

  const hostnames = new Set<string>();
  for (const record of payload) {
    for (const rawName of namesIn(record)) {
      const hostname = toHostname(rawName);
      if (hostname === null) continue;
      if (apexOf(hostname) === null) continue;
      if (!isUnderApex(hostname, apex)) continue;
      hostnames.add(hostname);
    }
  }

  return [...hostnames].sort().map((hostname) => ({ hostname, source: 'ct-log' as const }));
}
