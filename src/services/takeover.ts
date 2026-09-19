import { Resolver } from 'node:dns/promises';
import type { FindingConfidence } from '../db/schema.js';

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
    cnameSuffixes: ['.s3.amazonaws.com', '.s3-website.amazonaws.com', '.amazonaws.com'],
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

function defaultFetchImpl(): TakeoverFetchImpl {
  return async (url) => {
    const response = await fetch(url, { redirect: 'follow' });
    return response.text();
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
  try {
    const body = await fetchImpl(`https://${hostname}/`);
    return fingerprint.unclaimedMarkers.some((marker) => body.includes(marker));
  } catch {
    return false;
  }
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
    fingerprint !== null && (await servesUnclaimedMarker(normalised, fingerprint, options.fetchImpl ?? defaultFetchImpl()))
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
