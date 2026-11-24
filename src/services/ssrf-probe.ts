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
  tier: 'oob';
  protocols: ('dns' | 'http')[];
  callerSourceIp: string;
  observedAt: string;
};

// One verdict per fired (target, param). `context` is whatever the caller passed to
// `fire` (the scanner passes its scan-target id) so outcomes route back without the
// probe knowing about the database.
export type SsrfOutcome<C> = {
  context: C;
  url: string;
  param: string;
  payload: string;
  outcome: 'confirmed' | 'not_vulnerable';
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

type Pending<C> = { context: C; url: string; param: string; payload: string; hits: CollaboratorHit[] };

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
        pending.set(token, { context, url: target.toString(), param, payload, hits: [] });
        const mutated = new URL(target);
        mutated.searchParams.set(param, payload);
        fires.push(fetchImpl(mutated.toString()).catch(() => undefined));
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
          entry.hits.push(hit);
        }
      }

      const outcomes = [...pending.values()].map((entry): SsrfOutcome<C> => {
        const { context, url, param, payload, hits } = entry;
        const first = hits[0];
        if (first === undefined) return { context, url, param, payload, outcome: 'not_vulnerable' };
        return {
          context,
          url,
          param,
          payload,
          outcome: 'confirmed',
          evidence: {
            kind: 'ssrf',
            url,
            param,
            tier: 'oob',
            protocols: [...new Set(hits.map((h) => h.protocol))],
            callerSourceIp: first.callerSourceIp,
            observedAt: first.observedAt.toISOString(),
          },
        };
      });
      pending.clear();
      return outcomes;
    },
  };
}
