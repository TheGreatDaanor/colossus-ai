import { Resolver } from 'node:dns/promises';
import { and, asc, eq } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import { enumeratedHosts, programs, takeoverFindings, type FindingConfidence, type FindingSeverity } from '../db/schema.js';
import { ProgramValidationError } from './programs.js';

// The DNS surface this check needs, narrowed to two questions: what does this
// name CNAME to, and does this name resolve to an address? Injected as an option
// so every test stubs it and none performs live DNS.
export type DnsResolverImpl = {
  resolveCname(hostname: string): Promise<string[]>;
  resolveAddresses(hostname: string): Promise<string[]>;
};

// Fetching the hostname is narrowed to "give me the response body as text", so
// tests stub it and no test — and no fingerprint match — touches the network.
export type TakeoverFetchImpl = (url: string) => Promise<string>;

export type TakeoverEvidence = {
  hostname: string;
  cnameTarget: string;
  // Null when the CNAME target matches no entry in the fingerprint table: the
  // dangling reference alone is then all the evidence there is.
  provider: string | null;
  confidence: FindingConfidence;
  // What the operator should do. Names the provider and the resource so they can
  // reclaim or remove it themselves — Colossus never claims it.
  remediation: string;
};

export type CheckTakeoverOptions = { resolverImpl?: DnsResolverImpl; fetchImpl?: TakeoverFetchImpl };

// Hand-maintained in-repo and never fetched at runtime: a third party must not
// be able to change what Colossus asserts as `definitive`. `cnameSuffixes` say
// which provider a dangling target belongs to; `unclaimedMarkers` are strings
// the provider itself serves when the resource behind the name is unclaimed.
// The table grows on demand — an unlisted provider still reports at `possible`.
type ProviderFingerprint = {
  provider: string;
  cnameSuffixes: readonly string[];
  unclaimedMarkers: readonly string[];
};

const PROVIDER_FINGERPRINTS: readonly ProviderFingerprint[] = [
  {
    provider: 'Amazon S3',
    // Deliberately no bare `.amazonaws.com`: that suffix also covers ELB, API
    // Gateway and every other AWS service, and naming the wrong provider sends
    // the operator to the wrong console. An unlisted AWS service stays unknown.
    cnameSuffixes: ['.s3.amazonaws.com', '.s3-website.amazonaws.com', '.s3.dualstack.amazonaws.com'],
    unclaimedMarkers: ['NoSuchBucket', 'The specified bucket does not exist'],
  },
  {
    provider: 'GitHub Pages',
    cnameSuffixes: ['.github.io'],
    unclaimedMarkers: ["There isn't a GitHub Pages site here.", 'For root URLs (like http://example.com/) you must provide an index.html file'],
  },
  {
    provider: 'Heroku',
    cnameSuffixes: ['.herokudns.com', '.herokuapp.com', '.herokussl.com'],
    unclaimedMarkers: ['No such app', "There's nothing here, yet."],
  },
  {
    provider: 'Azure',
    cnameSuffixes: ['.azurewebsites.net', '.cloudapp.azure.com', '.trafficmanager.net'],
    unclaimedMarkers: ['Error 404 - Web app not found.', '404 Web Site not found'],
  },
  {
    provider: 'Fastly',
    cnameSuffixes: ['.fastly.net', '.fastlylb.net'],
    unclaimedMarkers: ['Fastly error: unknown domain'],
  },
  {
    provider: 'Shopify',
    cnameSuffixes: ['.myshopify.com'],
    unclaimedMarkers: ['Sorry, this shop is currently unavailable.', 'Only one step left!'],
  },
];

function matchProvider(cnameTarget: string): ProviderFingerprint | null {
  return (
    PROVIDER_FINGERPRINTS.find((entry) => entry.cnameSuffixes.some((suffix) => cnameTarget.endsWith(suffix))) ?? null
  );
}

function remediationFor(hostname: string, cnameTarget: string, provider: string | null): string {
  if (provider === null) {
    return `Remove the CNAME on ${hostname}, or restore the resource it points at (${cnameTarget}). Colossus has not claimed it.`;
  }
  return `Reclaim the ${provider} resource "${cnameTarget}" or remove the CNAME on ${hostname}. Colossus has not claimed the resource.`;
}

// A host that never answers must not hold a check open, and a body is read only
// as far as a fingerprint could possibly match: the response comes from a name
// the operator no longer controls, so its size is not ours to trust.
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

export type TakeoverFetchOptions = { timeoutMs?: number; maxBytes?: number };

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const body = response.body;
  if (body === null) return '';

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let bytes = 0;

  try {
    while (bytes < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const chunk = value.subarray(0, maxBytes - bytes);
      bytes += chunk.length;
      text += decoder.decode(chunk, { stream: true });
    }
    text += decoder.decode();
  } finally {
    await reader.cancel().catch(() => {});
  }

  return text;
}

export function createTakeoverFetch(options: TakeoverFetchOptions = {}): TakeoverFetchImpl {
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BODY_BYTES;

  return async (url) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { redirect: 'follow', signal: controller.signal });
      return await readBoundedText(response, maxBytes);
    } finally {
      clearTimeout(timer);
    }
  };
}

// A chain longer than this is pathological rather than a real delegation, and
// the `seen` set below catches loops shorter than the cap.
const MAX_CNAME_HOPS = 10;

// The resolver codes that mean "this name has no such record", as opposed to
// "the resolver could not tell us". Only the former is evidence.
const ABSENT_CODES = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);

function errorCode(err: unknown): string | null {
  if (typeof err !== 'object' || err === null) return null;
  const { code } = err as { code?: unknown };
  return typeof code === 'string' ? code : null;
}

function isAbsent(err: unknown): boolean {
  const code = errorCode(err);
  return code !== null && ABSENT_CODES.has(code);
}

function normaliseHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

function defaultResolverImpl(): DnsResolverImpl {
  const resolver = new Resolver();
  return {
    resolveCname: (hostname) => resolver.resolveCname(hostname),
    resolveAddresses: (hostname) => resolver.resolve4(hostname),
  };
}

// `absent` distinguishes "no such record" from "the resolver failed", because
// only the first is evidence about the name.
type Lookup = { found: string[] } | { absent: true } | { failed: true };

async function lookup(query: () => Promise<string[]>): Promise<Lookup> {
  try {
    return { found: await query() };
  } catch (err) {
    return isAbsent(err) ? { absent: true } : { failed: true };
  }
}

// Walks the CNAME chain to its end. Returns the final target, or null when the
// host has no CNAME, the chain loops, or the resolver could not answer.
async function resolveCnameChain(hostname: string, resolverImpl: DnsResolverImpl): Promise<string | null> {
  const seen = new Set<string>([hostname]);
  let current = hostname;
  let target: string | null = null;

  for (let hop = 0; hop < MAX_CNAME_HOPS; hop += 1) {
    const result = await lookup(() => resolverImpl.resolveCname(current));
    if ('failed' in result) return null;
    if ('absent' in result) return target;

    const next = result.found[0];
    if (next === undefined) return target;

    const normalised = normaliseHostname(next);
    if (seen.has(normalised)) return null;

    seen.add(normalised);
    target = normalised;
    current = normalised;
  }

  return null;
}

// Asks the hostname itself — not the provider resource — what it serves, because
// that is the request an attacker's victim would make. A host that cannot be
// reached is the common case for a dangling reference and is not an error here:
// it simply yields no fingerprint evidence.
async function servesUnclaimedMarker(
  hostname: string,
  fingerprint: ProviderFingerprint,
  fetchImpl: TakeoverFetchImpl,
): Promise<boolean> {
  // https first, then plain http: a dangling reference typically has no
  // certificate valid for this hostname, so https fails before the provider's
  // own words are ever seen. The http attempt reads a response, nothing more.
  for (const url of [`https://${hostname}/`, `http://${hostname}/`]) {
    try {
      const body = await fetchImpl(url);
      return fingerprint.unclaimedMarkers.some((marker) => body.includes(marker));
    } catch {
      continue;
    }
  }
  return false;
}

// A takeover is a dangling *reference*: the host still CNAMEs somewhere, but the
// provider resource at the end of that chain no longer resolves, so anyone who
// claims that resource serves content under the operator's own name. A host with
// no CNAME cannot be taken over this way, and a chain ending somewhere that
// resolves is healthy.
//
// The check fails closed: a resolver that cannot answer produces no evidence,
// because reporting nothing beats reporting a takeover that is not there.
export async function checkTakeover(hostname: string, options: CheckTakeoverOptions = {}): Promise<TakeoverEvidence | null> {
  const resolverImpl = options.resolverImpl ?? defaultResolverImpl();
  const normalised = normaliseHostname(hostname);

  const cnameTarget = await resolveCnameChain(normalised, resolverImpl);
  if (cnameTarget === null) return null;

  const addresses = await lookup(() => resolverImpl.resolveAddresses(cnameTarget));
  if (!('absent' in addresses)) return null;

  const fingerprint = matchProvider(cnameTarget);
  const provider = fingerprint?.provider ?? null;

  // `definitive` needs the provider's own words: the dangling reference says the
  // target is gone, but only an unclaimed-resource response proves the resource
  // is there to be claimed. Anything less — no fingerprint for this provider, an
  // unrecognised body, or nothing serving at all — stays `possible`.
  const confidence: FindingConfidence =
    fingerprint !== null && (await servesUnclaimedMarker(normalised, fingerprint, options.fetchImpl ?? createTakeoverFetch()))
      ? 'definitive'
      : 'possible';

  return {
    hostname: normalised,
    cnameTarget,
    provider,
    confidence,
    remediation: remediationFor(normalised, cnameTarget, provider),
  };
}


// A persisted takeover finding joined to the host it was found on. `hostname`
// comes from `enumerated_hosts` rather than being stored twice: the finding is
// keyed to the host row, which already holds the authoritative name.
export type TakeoverFinding = typeof takeoverFindings.$inferSelect & { hostname: string };

export type TakeoverServiceOptions = { resolverImpl?: DnsResolverImpl; fetchImpl?: TakeoverFetchImpl };

// A dangling reference is a real exposure whether or not the provider's own
// words confirm it, so both confidences are actionable; the provider-confirmed
// case is rated higher because the resource is demonstrably there to be claimed.
function severityFor(confidence: FindingConfidence): FindingSeverity {
  return confidence === 'definitive' ? 'high' : 'medium';
}

// Runs the takeover check across a program's inventory and persists what it
// finds. Deepens this module rather than living apart from `checkTakeover`: the
// pure per-host check and the program-wide sweep are one domain, and only the
// sweep needs the database.
export class TakeoverService {
  #db: Db;
  #resolverImpl: DnsResolverImpl | undefined;
  #fetchImpl: TakeoverFetchImpl | undefined;

  constructor(db: Db, options: TakeoverServiceOptions = {}) {
    this.#db = db;
    this.#resolverImpl = options.resolverImpl;
    this.#fetchImpl = options.fetchImpl;
  }

  // Checks every in-scope host in the program's inventory and returns the
  // findings. Only `in_scope`, non-wildcard hosts are checked: an out-of-scope
  // or unscoped host was never authorized, and a wildcard row stands for a
  // subtree rather than a name that answers. A host that has healed since a
  // prior run has its stale finding removed, so the list never overstates risk.
  async checkProgram(programId: number): Promise<TakeoverFinding[]> {
    this.#requireProgram(programId);

    const hosts = this.#db
      .select()
      .from(enumeratedHosts)
      .where(
        and(
          eq(enumeratedHosts.programId, programId),
          eq(enumeratedHosts.scopeStatus, 'in_scope'),
          eq(enumeratedHosts.isWildcard, false),
        ),
      )
      .orderBy(asc(enumeratedHosts.hostname))
      .all();

    // Built by spread so an unset impl stays absent rather than present-and-
    // undefined, which `exactOptionalPropertyTypes` distinguishes; checkTakeover
    // then falls back to its live defaults.
    const checkOptions: CheckTakeoverOptions = {
      ...(this.#resolverImpl ? { resolverImpl: this.#resolverImpl } : {}),
      ...(this.#fetchImpl ? { fetchImpl: this.#fetchImpl } : {}),
    };

    for (const host of hosts) {
      const evidence = await checkTakeover(host.hostname, checkOptions);

      if (evidence === null) {
        this.#db.delete(takeoverFindings).where(eq(takeoverFindings.enumeratedHostId, host.id)).run();
        continue;
      }

      const values = {
        cnameTarget: evidence.cnameTarget,
        provider: evidence.provider,
        severity: severityFor(evidence.confidence),
        confidence: evidence.confidence,
        remediation: evidence.remediation,
        createdAt: new Date(),
      };

      this.#db
        .insert(takeoverFindings)
        .values({ enumeratedHostId: host.id, ...values })
        // One finding per host: a re-check refreshes the evidence in place rather
        // than stacking a second row for the same dangling reference.
        .onConflictDoUpdate({ target: takeoverFindings.enumeratedHostId, set: values })
        .run();
    }

    return this.listFindings(programId);
  }

  // The program's persisted takeover findings, ordered by hostname so the list
  // reads the same way twice. Joined to the inventory to carry the hostname and
  // to scope the query to this program's hosts.
  async listFindings(programId: number): Promise<TakeoverFinding[]> {
    this.#requireProgram(programId);

    const rows = this.#db
      .select({ finding: takeoverFindings, hostname: enumeratedHosts.hostname })
      .from(takeoverFindings)
      .innerJoin(enumeratedHosts, eq(takeoverFindings.enumeratedHostId, enumeratedHosts.id))
      .where(eq(enumeratedHosts.programId, programId))
      .orderBy(asc(enumeratedHosts.hostname))
      .all();

    return rows.map((row) => ({ ...row.finding, hostname: row.hostname }));
  }

  #requireProgram(id: number): void {
    const row = this.#db.select({ id: programs.id }).from(programs).where(eq(programs.id, id)).get();
    if (!row) throw new ProgramValidationError(`program ${id} not found`);
  }
}
