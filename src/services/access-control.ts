import { createHash } from 'node:crypto';

// An operator-supplied principal: an opaque header bundle (a `Cookie` or
// `Authorization` set) attached verbatim to that identity's requests — Colossus
// never parses or refreshes it — plus the URLs the operator declares private to
// it. Identities are ephemeral scan inputs and are never persisted.
export interface Identity {
  label: string;
  headers: Record<string, string>;
  privateUrls: string[];
}

// One side of the three-way differential: the response an identity received,
// reduced to its status and a digest of the normalized body. No body content is
// kept here — a confirmed finding must never carry the victim's private data.
export type AccessControlResponseProof = {
  label: string;
  status: number;
  digest: string;
};

export type AccessControlProof = {
  url: string;
  owner: AccessControlResponseProof;
  unauthorized: AccessControlResponseProof;
  // The no-auth control has no identity label of its own — it is the synthesized
  // empty identity — so it records only status and digest.
  noAuth: { status: number; digest: string };
};

export type AccessControlOutcome = {
  category: 'idor' | 'unauthenticated-resource-access';
  url: string;
  ownerLabel: string;
  // The principal that reached the owner's resource: a peer identity for `idor`,
  // the synthesized no-auth control for `unauthenticated-resource-access`.
  unauthorizedLabel: string;
  proof: AccessControlProof;
};

// A ground-truth fetch that came back as an authentication failure — the identity
// could not retrieve its own declared-private URL, so its session has gone stale.
// This is a reported condition, not a finding: without valid ground truth there is
// nothing to compare peers against, so no `idor`/`unauthenticated-resource-access`
// may be fabricated for the URL. Carries no body — only the identity, URL and
// status the operator needs to know which identity to re-supply.
export type AccessControlError = {
  url: string;
  ownerLabel: string;
  status: number;
  message: string;
};

export type AccessControlResult = {
  outcomes: AccessControlOutcome[];
  errors: AccessControlError[];
};

// The synthesized no-auth control has no operator-supplied label. When it is the
// unauthorized principal (an `unauthenticated-resource-access` hit) this stands in
// for one, so the proof still names both sides of the differential.
const NO_AUTH_LABEL = 'no-auth';

// The replay seam: a URL plus the identity's opaque headers in, a status and body
// out. Injected so the oracle is exercised without live sessions or network; the
// scanner supplies an SSRF-guarded implementation in production.
export type HeaderedFetchImpl = (
  url: string,
  headers: Record<string, string>,
) => Promise<{ status: number; body: string }>;

// Whitespace-insensitive digest of a response: two responses that differ only in
// incidental formatting are treated as the same resource, so the oracle keys on
// what the page *is*, not how it was serialized. Status is folded in because a
// 200 body and a 403 body that happen to normalize alike are still different
// outcomes.
function digestResponse(status: number, body: string): string {
  const normalized = body.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${status}\n${normalized}`).digest('hex');
}

// An owner ground-truth fetch that returns 401 or any 3xx redirect (typically a
// bounce to a login page) means the identity's own session no longer authenticates
// it — a stale session. Distinct from a plain 403/404/500, which is a genuine
// "forbidden"/"not here"/"broken" response the identity did reach: that stays a
// silent no-finding, since an identical peer response there is a shared error page,
// not a leaked private resource.
function isStaleSession(status: number): boolean {
  return status === 401 || (status >= 300 && status < 400);
}

// Confirms horizontal IDOR by cross-identity replay. The empty (no-auth) identity
// is synthesized as a negative control; for each identity's declared-private URL
// the owner is fetched as ground truth, then replayed as every other identity and
// as the no-auth control. An `idor` fires when a peer's response matches the
// owner's ground truth AND the no-auth control diverges — i.e. the resource is
// gated (logged-out users are turned away) yet a different logged-in user still
// receives it. When the no-auth control instead *matches* the owner ground truth
// while some peer is still turned away, the resource is gated yet reachable with no
// session at all — an `unauthenticated-resource-access` finding. A resource
// everyone sees identically is public and produces no finding either way.
export async function runAccessControlChecks(
  identities: Identity[],
  fetchImpl: HeaderedFetchImpl,
): Promise<AccessControlResult> {
  const outcomes: AccessControlOutcome[] = [];
  const errors: AccessControlError[] = [];

  for (const owner of identities) {
    for (const url of owner.privateUrls) {
      // A dead or unreachable URL is isolated to itself: skipping it here keeps
      // every other URL and identity in the same scan still producing findings,
      // rather than one bad URL discarding the whole pass.
      try {
        const result = await checkUrl(owner, url, identities, fetchImpl);
        outcomes.push(...result.outcomes);
        if (result.error !== null) errors.push(result.error);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.warn(`access-control replay of ${url} as ${owner.label} failed: ${message}`);
      }
    }
  }

  return { outcomes, errors };
}

// The three-way differential for one owner/URL pair. Kept separate so a fetch
// failure on one URL can be isolated by the caller without losing the rest.
async function checkUrl(
  owner: Identity,
  url: string,
  identities: Identity[],
  fetchImpl: HeaderedFetchImpl,
): Promise<{ outcomes: AccessControlOutcome[]; error: AccessControlError | null }> {
  const ownerResponse = await fetchImpl(url, owner.headers);
  // A stale owner session — the identity cannot retrieve its own declared-private
  // URL (a 401 or a redirect to login) — is a reported error, not a silent miss:
  // without valid ground truth there is nothing to compare against, so no finding is
  // fabricated, but the operator is told which identity to re-supply. Colossus never
  // attempts to re-authenticate (identities are opaque; see ADR 0002).
  if (isStaleSession(ownerResponse.status)) {
    return {
      outcomes: [],
      error: {
        url,
        ownerLabel: owner.label,
        status: ownerResponse.status,
        message: `identity '${owner.label}' could not retrieve its own declared-private URL ${url} (status ${ownerResponse.status}) — its session appears stale; re-supply the identity`,
      },
    };
  }
  // Ground truth is only ground truth if the owner actually received the resource.
  // A plain owner 403/404/500 is a genuine error the identity did reach, not a
  // private resource anyone can leak, so an identical peer response there is a
  // shared error page, not an IDOR. Gating on 2xx keeps those out.
  if (ownerResponse.status < 200 || ownerResponse.status >= 300) return { outcomes: [], error: null };
  const ownerDigest = digestResponse(ownerResponse.status, ownerResponse.body);

  // The no-auth request does double duty: the negative control for `idor` and the
  // probe for `unauthenticated-resource-access` below. One request per URL, both jobs.
  const noAuthResponse = await fetchImpl(url, {});
  const noAuthDigest = digestResponse(noAuthResponse.status, noAuthResponse.body);

  // No-auth received exactly the owner's resource. Whether that is a leak or just a
  // public page turns on whether the resource is access-controlled at all: if some
  // peer identity is turned away (a digest that differs from the owner's), the
  // resource genuinely varies by principal yet is served to an anonymous request —
  // unauthenticated access to a private resource. If every identity sees it
  // identically, nobody's access is distinguished and it is simply public: no
  // finding. Reuses the existing no-auth control; no new request for it.
  if (noAuthDigest === ownerDigest) {
    for (const peer of identities) {
      if (peer === owner) continue;

      const peerResponse = await fetchImpl(url, peer.headers);
      const peerDigest = digestResponse(peerResponse.status, peerResponse.body);
      if (peerDigest === ownerDigest) continue;

      // A distinguishing peer proves the resource is gated; the no-auth control got
      // in anyway. One finding per URL — the defect is that the URL is reachable
      // unauthenticated, a single fact, not one per turned-away peer.
      return {
        outcomes: [
        {
          category: 'unauthenticated-resource-access',
          url,
          ownerLabel: owner.label,
          unauthorizedLabel: NO_AUTH_LABEL,
          proof: {
            url,
            owner: { label: owner.label, status: ownerResponse.status, digest: ownerDigest },
            unauthorized: { label: NO_AUTH_LABEL, status: noAuthResponse.status, digest: noAuthDigest },
            noAuth: { status: noAuthResponse.status, digest: noAuthDigest },
          },
        },
        ],
        error: null,
      };
    }
    return { outcomes: [], error: null };
  }

  const outcomes: AccessControlOutcome[] = [];
  for (const peer of identities) {
    if (peer === owner) continue;

    const peerResponse = await fetchImpl(url, peer.headers);
    const peerDigest = digestResponse(peerResponse.status, peerResponse.body);
    if (peerDigest !== ownerDigest) continue;

    outcomes.push({
      category: 'idor',
      url,
      ownerLabel: owner.label,
      unauthorizedLabel: peer.label,
      proof: {
        url,
        owner: { label: owner.label, status: ownerResponse.status, digest: ownerDigest },
        unauthorized: { label: peer.label, status: peerResponse.status, digest: peerDigest },
        noAuth: { status: noAuthResponse.status, digest: noAuthDigest },
      },
    });
  }
  return { outcomes, error: null };
}
