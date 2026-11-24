import type { BodyFetchImpl } from './active-scanner.js';

// The scan's only view of the collaborator: the self-hosted listener a target's
// server can be induced to contact. `mint` hands out a fresh, globally unique token
// and the URL that carries it; `poll` reports which of the given tokens have called
// back so far. Injected so every confirmation branch runs against a fake.
export interface CollaboratorClient {
  mint(): { token: string; url: string };
  poll(tokens: string[]): Promise<CollaboratorHit[]>;
}

export type CollaboratorHit = {
  token: string;
  protocol: 'dns' | 'http';
  callerSourceIp: string;
  observedAt: Date;
};

// Body-free proof for a confirmed SSRF, stored as `structured_evidence`.
export type SsrfEvidence = {
  kind: 'ssrf';
  url: string;
  param: string;
  tier: 'oob' | 'internal-read';
  // Empty, with no caller IP or timestamp, on an internal read confirmed without a callback.
  protocols: ('dns' | 'http')[];
  callerSourceIp?: string;
  observedAt?: string;
  matchedSignature?: string;
  // On an `oob` finding whose metadata probe did not match: credential theft was
  // neither proven nor ruled out (IMDSv2, a non-AWS host, or a non-reflecting fetch).
  internalRead?: 'not-demonstrated';
};

// The one internal target a forged GET can read without a token or special header.
export const IMDSV1_METADATA_URL = 'http://169.254.169.254/latest/meta-data/';
export const IMDSV1_SIGNATURE = 'aws-imdsv1-metadata-listing';

// Lines only the IMDSv1 metadata listing returns, each standing alone on its line.
// None is a substring of the payload URL, so a target echoing the payload never matches.
const IMDS_LISTING_LINES = ['ami-id', 'instance-id', 'instance-type', 'local-ipv4', 'local-hostname', 'reservation-id'];
const IMDS_MIN_MATCHES = 4;

function matchesImdsListing(body: string): boolean {
  const lines = new Set(body.split(/\r?\n/).map((line) => line.replace(/<[^>]*>/g, '').trim()));
  return IMDS_LISTING_LINES.filter((line) => lines.has(line)).length >= IMDS_MIN_MATCHES;
}

// One verdict per fired (target, param). `context` is whatever the caller passed to
// `fire` (the scanner passes its scan-target id) so outcomes route back without the
// probe knowing about the database. `outcome` is the `oob` attempt's verdict alone;
// `internalRead` is present only on a signature match (a miss has no honest negative).
// `evidence` and `severity` are present when either signal confirmed — one finding per
// (target, param), at the highest tier.
export type SsrfOutcome<C> = {
  context: C;
  url: string;
  param: string;
  payload: string;
  outcome: 'confirmed' | 'not_vulnerable';
  internalRead?: { payload: string; matchedSignature: string };
  severity?: 'high' | 'critical';
  evidence?: SsrfEvidence;
};

export type DrainTiming = {
  windowMs: number;
  pollIntervalMs: number;
  sleep?: (ms: number) => Promise<void>;
};

export interface SsrfProbe<C> {
  // Sends a collaborator URL into every query param of `target`, registering each
  // token as pending. Fetch failures are swallowed: the target may still have made
  // the outbound request, and the drain is what decides.
  fire(target: URL, context: C): Promise<void>;
  // The scan-level barrier: polls the collaborator across one bounded window and
  // resolves every pending token. Returns immediately when nothing was fired.
  drainCollaborator(): Promise<SsrfOutcome<C>[]>;
}

// `earliest` keeps one hit per protocol — the earliest seen — so a cumulative
// listener buffer re-reported on every poll never grows it, and a DNS+HTTP pair for
// one token folds into a single verdict.
type Pending<C> = {
  context: C;
  url: string;
  param: string;
  payload: string;
  earliest: Map<'dns' | 'http', CollaboratorHit>;
  internalReadMatched: boolean;
};

const PROTOCOL_ORDER: readonly ('dns' | 'http')[] = ['dns', 'http'];

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Out-of-band SSRF as a two-phase probe, deliberately not an InjectionClass: its
// verdict arrives later, from the collaborator, not from the injected response.
export function makeSsrfProbe<C>(
  fetchImpl: BodyFetchImpl,
  collaborator: CollaboratorClient,
  timing: DrainTiming = { windowMs: 30_000, pollIntervalMs: 3_000 },
): SsrfProbe<C> {
  const pending = new Map<string, Pending<C>>();
  const sleep = timing.sleep ?? defaultSleep;

  return {
    async fire(target, context) {
      const fires: Promise<unknown>[] = [];
      for (const param of new Set(target.searchParams.keys())) {
        const { token, url: payload } = collaborator.mint();
        const entry: Pending<C> = {
          context,
          url: target.toString(),
          param,
          payload,
          earliest: new Map(),
          internalReadMatched: false,
        };
        pending.set(token, entry);
        const mutated = new URL(target);
        mutated.searchParams.set(param, payload);
        fires.push(fetchImpl(mutated.toString()).catch(() => undefined));
        // The in-band signal: the reflected body is checked here and never kept.
        const metadata = new URL(target);
        metadata.searchParams.set(param, IMDSV1_METADATA_URL);
        fires.push(
          fetchImpl(metadata.toString()).then(
            ({ body }) => {
              if (matchesImdsListing(body)) entry.internalReadMatched = true;
            },
            () => undefined,
          ),
        );
      }
      await Promise.all(fires);
    },

    async drainCollaborator() {
      if (pending.size === 0) return [];
      const tokens = [...pending.keys()];
      const polls = Math.max(1, Math.ceil(timing.windowMs / timing.pollIntervalMs));
      for (let i = 0; i < polls; i++) {
        await sleep(timing.pollIntervalMs);
        const seen = await collaborator.poll(tokens);
        for (const hit of seen) {
          const entry = pending.get(hit.token);
          if (entry === undefined) continue;
          const known = entry.earliest.get(hit.protocol);
          if (known === undefined || hit.observedAt < known.observedAt) entry.earliest.set(hit.protocol, hit);
        }
      }

      const outcomes = [...pending.values()].map((entry): SsrfOutcome<C> => {
        const { context, url, param, payload } = entry;
        const hits = [...entry.earliest.values()];
        const first = hits.reduce<CollaboratorHit | undefined>(
          (soonest, hit) => (soonest === undefined || hit.observedAt < soonest.observedAt ? hit : soonest),
          undefined,
        );
        const outcome = first === undefined ? 'not_vulnerable' : 'confirmed';
        const base = { context, url, param, payload, outcome } as const;
        if (!entry.internalReadMatched && first === undefined) return base;
        const callback =
          first === undefined
            ? {}
            : { callerSourceIp: first.callerSourceIp, observedAt: first.observedAt.toISOString() };
        const protocols = PROTOCOL_ORDER.filter((p) => entry.earliest.has(p));
        if (entry.internalReadMatched) {
          return {
            ...base,
            internalRead: { payload: IMDSV1_METADATA_URL, matchedSignature: IMDSV1_SIGNATURE },
            severity: 'critical',
            evidence: {
              kind: 'ssrf',
              url,
              param,
              tier: 'internal-read',
              protocols,
              ...callback,
              matchedSignature: IMDSV1_SIGNATURE,
            },
          };
        }
        return {
          ...base,
          severity: 'high',
          evidence: { kind: 'ssrf', url, param, tier: 'oob', protocols, ...callback, internalRead: 'not-demonstrated' },
        };
      });
      pending.clear();
      return outcomes;
    },
  };
}
