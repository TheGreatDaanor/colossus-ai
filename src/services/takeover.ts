import { Resolver } from 'node:dns/promises';
import type { FindingConfidence } from '../db/schema.js';

// The DNS surface this check needs, narrowed to two questions: what does this
// name CNAME to, and does this name resolve to an address? Injected as an option
// so every test stubs it and none performs live DNS.
export type DnsResolverImpl = {
  resolveCname(hostname: string): Promise<string[]>;
  resolveAddresses(hostname: string): Promise<string[]>;
};

export type TakeoverEvidence = {
  hostname: string;
  cnameTarget: string;
  // Null until the fingerprint table lands: with no provider matched, the
  // dangling reference alone is all the evidence there is.
  provider: string | null;
  confidence: FindingConfidence;
};

export type CheckTakeoverOptions = { resolverImpl?: DnsResolverImpl };

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

  // Confidence is `possible` at this stage: the dangling reference is observed,
  // but nothing yet confirms the provider resource is actually claimable. The
  // fingerprint upgrade to `definitive` is a later issue.
  return { hostname: normalised, cnameTarget, provider: null, confidence: 'possible' };
}
