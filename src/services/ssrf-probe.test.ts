import { describe, expect, it } from 'vitest';
import type { CollaboratorClient, CollaboratorHit } from './ssrf-probe.js';
import { makeSsrfProbe } from './ssrf-probe.js';

// A fake collaborator plus a fake target that share one world: when the target
// "fetches" a URL whose `fetches` param holds a collaborator URL, the collaborator
// records a hit for that URL's token — exactly what a vulnerable server would cause.
function fakeWorld(vulnerableParams: string[]) {
  let minted = 0;
  const tokenByUrl = new Map<string, string>();
  const hits: CollaboratorHit[] = [];
  let polls = 0;

  const collaborator: CollaboratorClient = {
    mint() {
      minted += 1;
      const token = `tok${minted}`;
      const url = `http://${token}.collab.test/`;
      tokenByUrl.set(url, token);
      return { token, url };
    },
    async poll(tokens) {
      polls += 1;
      return hits.filter((h) => tokens.includes(h.token));
    },
  };

  const fetched: string[] = [];
  const fetchImpl = async (url: string) => {
    fetched.push(url);
    for (const [param, value] of new URL(url).searchParams) {
      const token = tokenByUrl.get(value);
      if (token !== undefined && vulnerableParams.includes(param)) {
        hits.push({ token, protocol: 'http', callerSourceIp: '203.0.113.7', observedAt: new Date(0) });
      }
    }
    return { body: '', headers: new Headers() };
  };

  return { collaborator, fetchImpl, fetched, pollCount: () => polls };
}

const instantDrain = { windowMs: 30_000, pollIntervalMs: 3_000, sleep: async () => {} };

describe('ssrf probe', () => {
  it('confirms an oob ssrf on the param whose collaborator url the target fetched', async () => {
    const world = fakeWorld(['url']);
    const probe = makeSsrfProbe<number>(world.fetchImpl, world.collaborator, instantDrain);

    await probe.fire(new URL('https://example.com/fetch?url=a&q=b'), 1);
    const outcomes = await probe.drainCollaborator();

    const byParam = new Map(outcomes.map((o) => [o.param, o]));
    expect(byParam.get('url')?.outcome).toBe('confirmed');
    expect(byParam.get('url')?.evidence).toEqual({
      kind: 'ssrf',
      url: 'https://example.com/fetch?url=a&q=b',
      param: 'url',
      tier: 'oob',
      protocols: ['http'],
      callerSourceIp: '203.0.113.7',
      observedAt: new Date(0).toISOString(),
    });
    expect(byParam.get('q')?.outcome).toBe('not_vulnerable');
    expect(byParam.get('q')?.evidence).toBeUndefined();
    expect(outcomes.every((o) => o.context === 1)).toBe(true);
  });

  it('skips the drain window entirely when nothing was fired', async () => {
    const world = fakeWorld(['url']);
    const probe = makeSsrfProbe<number>(world.fetchImpl, world.collaborator, instantDrain);

    await probe.fire(new URL('https://example.com/no-params'), 1);
    const outcomes = await probe.drainCollaborator();

    expect(outcomes).toEqual([]);
    expect(world.pollCount()).toBe(0);
  });

  it('gives every injection point its own token, across targets', async () => {
    const world = fakeWorld(['a']);
    const probe = makeSsrfProbe<number>(world.fetchImpl, world.collaborator, instantDrain);

    await probe.fire(new URL('https://example.com/x?a=1&b=2'), 1);
    await probe.fire(new URL('https://example.com/y?a=1'), 2);
    const outcomes = await probe.drainCollaborator();

    const payloads = outcomes.map((o) => o.payload);
    expect(new Set(payloads).size).toBe(3);
    expect(outcomes.filter((o) => o.outcome === 'confirmed').map((o) => o.context).sort()).toEqual([1, 2]);
  });
});

describe('ssrf probe callback protocols', () => {
  // A collaborator whose buffer is cumulative — every poll returns every hit seen so
  // far, as the real listener does — scripted with whatever hits the test needs.
  function scriptedCollaborator(script: (token: string) => Omit<CollaboratorHit, 'token'>[]): CollaboratorClient {
    let minted = 0;
    return {
      mint() {
        minted += 1;
        const token = `tok${minted}`;
        return { token, url: `http://${token}.collab.test/` };
      },
      async poll(asked) {
        return asked.flatMap((token) => script(token).map((hit) => ({ token, ...hit })));
      },
    };
  }
  const noopFetch = async () => ({ body: '', headers: new Headers() });

  it('confirms a blind ssrf from a bare dns lookup with no http callback', async () => {
    const collaborator = scriptedCollaborator(() => [
      { protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: new Date(1_000) },
    ]);
    const probe = makeSsrfProbe<number>(noopFetch, collaborator, instantDrain);

    await probe.fire(new URL('https://example.com/?url=a'), 1);
    const [outcome] = await probe.drainCollaborator();

    expect(outcome?.outcome).toBe('confirmed');
    expect(outcome?.evidence?.protocols).toEqual(['dns']);
    expect(outcome?.evidence?.callerSourceIp).toBe('198.51.100.53');
  });

  it('folds a dns+http pair, repeated on every poll and reported out of order, into one outcome', async () => {
    const collaborator = scriptedCollaborator(() => [
      { protocol: 'http', callerSourceIp: '203.0.113.7', observedAt: new Date(2_000) },
      { protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: new Date(1_000) },
    ]);
    const probe = makeSsrfProbe<number>(noopFetch, collaborator, instantDrain);

    await probe.fire(new URL('https://example.com/?url=a'), 1);
    const outcomes = await probe.drainCollaborator();

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]?.evidence).toMatchObject({
      protocols: ['dns', 'http'],
      // The earliest callback is the one that confirmed.
      callerSourceIp: '198.51.100.53',
      observedAt: new Date(1_000).toISOString(),
    });
  });
});
