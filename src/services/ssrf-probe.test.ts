import { describe, expect, it } from 'vitest';
import type { CollaboratorClient, CollaboratorHit } from './ssrf-probe.js';
import { makeSsrfProbe, makeUnavailableSsrfProbe } from './ssrf-probe.js';

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
    selfTest: async () => ({ ok: true, ownEgressIps: [] }),
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
      internalRead: 'not-demonstrated',
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
      selfTest: async () => ({ ok: true, ownEgressIps: [] }),
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

describe('ssrf probe internal-read tier', () => {
  const METADATA = 'http://169.254.169.254/latest/meta-data/';
  const IMDS_LISTING = [
    'ami-id',
    'ami-launch-index',
    'ami-manifest-path',
    'block-device-mapping/',
    'hostname',
    'instance-action',
    'instance-id',
    'instance-type',
    'local-hostname',
    'local-ipv4',
    'mac',
    'network/',
    'placement/',
    'public-hostname',
    'public-ipv4',
    'reservation-id',
    'security-groups',
  ].join('\n');

  // A target that reflects whatever its `url` param fetches; `respond` decides what the
  // metadata payload returns. `callback` makes the collaborator payload call back too.
  function world(respond: (payload: string) => string, callback: boolean) {
    let minted = 0;
    const hits: CollaboratorHit[] = [];
    const tokenByUrl = new Map<string, string>();
    const collaborator: CollaboratorClient = {
      mint() {
        minted += 1;
        const token = `tok${minted}`;
        const url = `http://${token}.collab.test/`;
        tokenByUrl.set(url, token);
        return { token, url };
      },
      async poll(tokens) {
        return hits.filter((h) => tokens.includes(h.token));
      },
      selfTest: async () => ({ ok: true, ownEgressIps: [] }),
    };
    const fetched: string[] = [];
    const fetchImpl = async (url: string) => {
      fetched.push(url);
      const value = new URL(url).searchParams.get('url') ?? '';
      const token = tokenByUrl.get(value);
      if (token !== undefined && callback) {
        hits.push({ token, protocol: 'http', callerSourceIp: '203.0.113.7', observedAt: new Date(0) });
      }
      return { body: value === METADATA ? respond(value) : '', headers: new Headers() };
    };
    return { collaborator, fetchImpl, fetched };
  }

  async function run(w: ReturnType<typeof world>) {
    const probe = makeSsrfProbe<number>(w.fetchImpl, w.collaborator, instantDrain);
    await probe.fire(new URL('https://example.com/fetch?url=a'), 1);
    return probe.drainCollaborator();
  }

  it('fires the imdsv1 metadata payload at every param', async () => {
    const w = world(() => '', false);
    const probe = makeSsrfProbe<number>(w.fetchImpl, w.collaborator, instantDrain);
    await probe.fire(new URL('https://example.com/fetch?url=a&q=b'), 1);
    const metadataFetches = w.fetched.filter((u) => [...new URL(u).searchParams.values()].includes(METADATA));
    expect(metadataFetches).toHaveLength(2);
  });

  it('escalates to critical internal-read when the metadata listing is reflected, with no callback', async () => {
    const outcomes = await run(world(() => IMDS_LISTING, false));

    expect(outcomes).toHaveLength(1);
    const [o] = outcomes;
    expect(o?.outcome).toBe('not_vulnerable');
    expect(o?.severity).toBe('critical');
    expect(o?.internalRead).toEqual({ payload: METADATA, matchedSignature: 'aws-imdsv1-metadata-listing' });
    expect(o?.evidence).toEqual({
      kind: 'ssrf',
      url: 'https://example.com/fetch?url=a',
      param: 'url',
      tier: 'internal-read',
      protocols: [],
      matchedSignature: 'aws-imdsv1-metadata-listing',
    });
  });

  it('folds an oob callback and an internal read on one param into one critical outcome', async () => {
    const outcomes = await run(world(() => `<pre>${IMDS_LISTING}</pre>`, true));

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]?.outcome).toBe('confirmed');
    expect(outcomes[0]?.severity).toBe('critical');
    expect(outcomes[0]?.evidence).toMatchObject({
      tier: 'internal-read',
      protocols: ['http'],
      callerSourceIp: '203.0.113.7',
      matchedSignature: 'aws-imdsv1-metadata-listing',
    });
  });

  it('stays high/oob and marks the internal read not demonstrated when the signature misses', async () => {
    const outcomes = await run(world(() => '', true));

    expect(outcomes[0]?.severity).toBe('high');
    expect(outcomes[0]?.internalRead).toBeUndefined();
    expect(outcomes[0]?.evidence).toMatchObject({ tier: 'oob', internalRead: 'not-demonstrated' });
    expect(outcomes[0]?.evidence?.matchedSignature).toBeUndefined();
  });

  it.each([
    ['a bare 200 with an unrelated page', () => '<html><body>ok</body></html>'],
    ['an echo of the payload', (p: string) => `You asked for ${p}\n${p}`],
    ['an empty body', () => ''],
    ['a 401 error page', () => '401 Unauthorized'],
    ['a 400 error page', () => 'Bad Request'],
    ['a few listing words on one line', () => 'ami-id instance-id local-ipv4 hostname'],
  ])('never confirms an internal read from %s', async (_label, respond) => {
    const outcomes = await run(world(respond, false));

    expect(outcomes[0]?.internalRead).toBeUndefined();
    expect(outcomes[0]?.evidence).toBeUndefined();
    expect(outcomes[0]?.severity).toBeUndefined();
  });

  it('treats a metadata fetch failure as no signal', async () => {
    const w = world(() => IMDS_LISTING, false);
    const failing = async (url: string) => {
      if (url.includes(encodeURIComponent(METADATA))) throw new Error('refused');
      return w.fetchImpl(url);
    };
    const probe = makeSsrfProbe<number>(failing, w.collaborator, instantDrain);
    await probe.fire(new URL('https://example.com/fetch?url=a'), 1);
    const [o] = await probe.drainCollaborator();
    expect(o?.internalRead).toBeUndefined();
  });
});

describe('ssrf probe degraded outcomes', () => {
  // Every minted token calls back over http from `caller`; `failPolls` lists the
  // (1-based) poll numbers that throw, as an unreachable listener would.
  function callingBack(caller: string, failPolls: number[] = [], callsBack = (_token: string) => true) {
    let minted = 0;
    let polls = 0;
    const collaborator: CollaboratorClient = {
      mint() {
        minted += 1;
        return { token: `tok${minted}`, url: `http://tok${minted}.collab.test/` };
      },
      async poll(tokens) {
        polls += 1;
        if (failPolls.includes(polls)) throw new Error('ECONNREFUSED');
        return tokens
          .filter(callsBack)
          .map((token) => ({ token, protocol: 'http' as const, callerSourceIp: caller, observedAt: new Date(0) }));
      },
      selfTest: async () => ({ ok: true, ownEgressIps: [] }),
    };
    return collaborator;
  }
  const noopFetch = async () => ({ body: '', headers: new Headers() });

  it("discards a callback from colossus's own egress ip", async () => {
    const probe = makeSsrfProbe<number>(noopFetch, callingBack('192.0.2.10'), {
      ...instantDrain,
      ownEgressIps: ['192.0.2.10'],
    });
    await probe.fire(new URL('https://example.com/?url=a'), 1);
    const [o] = await probe.drainCollaborator();

    expect(o?.outcome).toBe('not_vulnerable');
    expect(o?.evidence).toBeUndefined();
    expect(probe.stats().ownEgressDiscarded).toBe(1);
  });

  it('marks unconfirmed points unavailable when a poll fails mid-drain, and still completes', async () => {
    // tok1 calls back, tok2 never does; poll 2 fails.
    const collaborator = callingBack('203.0.113.7', [2], (t) => t === 'tok1');
    const probe = makeSsrfProbe<number>(noopFetch, collaborator, instantDrain);
    await probe.fire(new URL('https://example.com/?a=1&b=2'), 1);
    const outcomes = await probe.drainCollaborator();

    const byParam = new Map(outcomes.map((o) => [o.param, o]));
    expect(byParam.get('a')?.outcome).toBe('confirmed');
    expect(byParam.get('b')?.outcome).toBe('unavailable');
    expect(byParam.get('b')?.error).toBe('collaborator-unreachable-mid-drain');
    expect(probe.stats()).toMatchObject({ fired: 2, received: 1, unavailable: 1 });
  });

  it('drops and counts, once, a hit for a token this scan is not waiting on', async () => {
    const collaborator: CollaboratorClient = {
      mint: () => ({ token: 'mine', url: 'http://mine.collab.test/' }),
      poll: async () => [{ token: 'stale', protocol: 'dns', callerSourceIp: '203.0.113.7', observedAt: new Date(0) }],
      selfTest: async () => ({ ok: true, ownEgressIps: [] }),
    };
    const probe = makeSsrfProbe<number>(noopFetch, collaborator, instantDrain);
    await probe.fire(new URL('https://example.com/?url=a'), 1);
    const [o] = await probe.drainCollaborator();

    expect(o?.outcome).toBe('not_vulnerable');
    expect(probe.stats().late).toBe(1);
  });

  it('an unavailable probe fires nothing and reports every param unavailable with its reason', async () => {
    const probe = makeUnavailableSsrfProbe<number>('collaborator-not-configured');
    await probe.fire(new URL('https://example.com/?a=1&b=2'), 7);
    const outcomes = await probe.drainCollaborator();

    expect(outcomes.map((o) => [o.param, o.outcome, o.error, o.context])).toEqual([
      ['a', 'unavailable', 'collaborator-not-configured', 7],
      ['b', 'unavailable', 'collaborator-not-configured', 7],
    ]);
    expect(probe.stats()).toMatchObject({ fired: 0, unavailable: 2 });
  });
});
