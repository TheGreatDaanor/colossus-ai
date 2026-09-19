import { Resolver } from 'node:dns/promises';
import { randomBytes } from 'node:crypto';
import type { HostSource } from '../db/schema.js';
import { apexOf } from './programs.js';

// A host observed by some source, before anything is known about its scope. The
// scope decision belongs to programs.ts and is made when the host is recorded.
// `isWildcard` marks a host that stands for a subtree rather than a name anyone
// has seen answer: a `*.` certificate identity, or every inferred host under an
// apex whose random-nonce label resolves. Absent means an ordinary host.
export type ObservedHost = { hostname: string; source: HostSource; isWildcard?: boolean };

// The CT query narrowed to "give me the decoded JSON for this apex". Injected so
// every test stubs it and no test contacts the real crt.sh endpoint.
export type CtFetchImpl = (apex: string) => Promise<unknown>;

// Thrown when the source could not be queried. The caller decides what that
// means: a scan treats it as non-fatal and keeps the inventory it already has.
export class EnumerationError extends Error {}

// The DNS surface wildcard detection needs, narrowed to one question: does this
// name resolve to an address? Injected so every test stubs it and none performs
// live DNS. A name that does not resolve raises, which is not an error here.
export type WildcardResolverImpl = { resolveAddresses(hostname: string): Promise<string[]> };

export type EnumerationServiceOptions = {
  ctFetchImpl?: CtFetchImpl;
  resolverImpl?: WildcardResolverImpl;
  nonceLabel?: () => string;
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

// Long enough that no operator has ever registered it as a real subdomain, so a
// resolving answer means the apex answers for everything rather than for this.
const NONCE_LABEL_BYTES = 12;

function randomNonceLabel(): string {
  return `colossus-wildcard-probe-${randomBytes(NONCE_LABEL_BYTES).toString('hex')}`;
}

// Real DNS. Errors are swallowed by the caller: NXDOMAIN and SERVFAIL both mean
// "no evidence of a wildcard", and neither is an enumeration failure.
function createWildcardResolver(): WildcardResolverImpl {
  const resolver = new Resolver();
  return {
    async resolveAddresses(hostname) {
      const [v4, v6] = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
      return [
        ...(v4.status === 'fulfilled' ? v4.value : []),
        ...(v6.status === 'fulfilled' ? v6.value : []),
      ];
    },
  };
}

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
// the root keeps the evidence without inventing a hostname nobody has seen, and
// the wildcard flag travels with it so the host is never scanned.
function toHostname(rawName: string): { hostname: string; isWildcard: boolean } | null {
  const name = normaliseHostname(rawName);
  const isWildcard = name.startsWith(WILDCARD_PREFIX);
  const hostname = isWildcard ? name.slice(WILDCARD_PREFIX.length) : name;
  return hostname === '' ? null : { hostname, isWildcard };
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
  #resolverImpl: WildcardResolverImpl;
  #nonceLabel: () => string;
  #cacheTtlMs: number;
  #maxCacheEntries: number;
  #now: () => number;
  #cache = new Map<string, CacheEntry>();

  constructor(options: EnumerationServiceOptions = {}) {
    this.#ctFetchImpl = options.ctFetchImpl ?? createCtFetch({ userAgent: options.userAgent ?? DEFAULT_USER_AGENT });
    this.#resolverImpl = options.resolverImpl ?? createWildcardResolver();
    this.#nonceLabel = options.nonceLabel ?? randomNonceLabel;
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
    const withWildcards = (await this.#isWildcardApex(normalisedApex))
      ? withWildcardApex(await this.#keepCorroborated(hosts, normalisedApex), normalisedApex)
      : hosts;
    this.#remember(normalisedApex, withWildcards);
    return withWildcards;
  }

  // Under a wildcard apex, a host inferred from a `*.` identity has nothing
  // behind it but the subtree the certificate covers. It is kept only when it
  // resolves in its own right; otherwise it would be a fictitious host.
  async #keepCorroborated(hosts: ObservedHost[], apex: string): Promise<ObservedHost[]> {
    const kept: ObservedHost[] = [];
    for (const host of hosts) {
      if (host.isWildcard !== true || host.hostname === apex) {
        kept.push(host);
        continue;
      }
      if (await this.#resolves(host.hostname)) kept.push(host);
    }
    return kept;
  }

  async #resolves(hostname: string): Promise<boolean> {
    try {
      return (await this.#resolverImpl.resolveAddresses(hostname)).length > 0;
    } catch {
      return false;
    }
  }

  // An apex that answers for a name nobody has ever registered answers for
  // everything, so resolution stops being evidence that a host exists.
  async #isWildcardApex(apex: string): Promise<boolean> {
    return this.#resolves(`${this.#nonceLabel()}.${apex}`);
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

// The apex carries the wildcard flag into the inventory, so the operator reading
// the host list can see why the hosts under it are not to be trusted. Nothing is
// invented: the apex is the name that was authorized and enumerated.
function withWildcardApex(hosts: ObservedHost[], apex: string): ObservedHost[] {
  const others = hosts.filter((host) => host.hostname !== apex);
  return [...others, { hostname: apex, source: 'ct-log' as const, isWildcard: true }].sort((a, b) =>
    a.hostname < b.hostname ? -1 : a.hostname > b.hostname ? 1 : 0,
  );
}

function collectHosts(payload: unknown, apex: string): ObservedHost[] {
  if (!Array.isArray(payload)) return [];

  // A hostname named both bare and behind a `*.` is a real host, so an ordinary
  // observation of it outweighs the wildcard identity that also covers it.
  const hostnames = new Map<string, boolean>();
  for (const record of payload) {
    for (const rawName of namesIn(record)) {
      const name = toHostname(rawName);
      if (name === null) continue;
      if (apexOf(name.hostname) === null) continue;
      if (!isUnderApex(name.hostname, apex)) continue;
      hostnames.set(name.hostname, (hostnames.get(name.hostname) ?? true) && name.isWildcard);
    }
  }

  return [...hostnames.keys()].sort().map((hostname) => ({
    hostname,
    source: 'ct-log' as const,
    ...(hostnames.get(hostname) === true ? { isWildcard: true } : {}),
  }));
}
