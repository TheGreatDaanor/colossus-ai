import { describe, expect, it } from 'vitest';
import { collaboratorFromEnv, makeHttpCollaboratorClient } from './collaborator-client.js';

type WireHit = { token: string; protocol: 'dns' | 'http'; callerSourceIp: string; observedAt: string };

// A stub of the listener's query API: answers `POST /hits` from `hitsFor`, and
// rejects any request not carrying the shared secret, as the real daemon does.
function stubQueryApi(hitsFor: (tokens: string[]) => WireHit[], secret = 's3cret') {
  const requests: { url: string; authorization: string | null; tokens: string[] }[] = [];
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    const { tokens } = JSON.parse(String(init?.body)) as { tokens: string[] };
    requests.push({ url: String(input), authorization: headers.get('authorization'), tokens });
    if (headers.get('authorization') !== `Bearer ${secret}`) return new Response('unauthorized', { status: 401 });
    return Response.json({ hits: hitsFor(tokens) });
  };
  return { fetchImpl, requests };
}

const config = {
  baseDomain: 'oast.example.net',
  queryUrl: 'https://listener.internal:8443/hits',
  secret: 's3cret',
  selfTestTiming: { attempts: 3, intervalMs: 1, sleep: async () => {} },
};

describe('http collaborator client', () => {
  it('mints a fresh dns-safe token per call, under the base domain', () => {
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: stubQueryApi(() => []).fetchImpl });
    const minted = Array.from({ length: 50 }, () => client.mint());

    expect(new Set(minted.map((m) => m.token)).size).toBe(50);
    for (const { token, url } of minted) {
      expect(token).toMatch(/^[a-z0-9]{20}$/);
      expect(url).toBe(`http://${token}.oast.example.net/`);
    }
  });

  it('polls the query api with the shared secret and parses hits', async () => {
    const api = stubQueryApi((tokens) =>
      tokens.map((token) => ({ token, protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: '2026-01-01T00:00:00.000Z' })),
    );
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    const hits = await client.poll(['abc', 'def']);

    expect(api.requests).toEqual([{ url: config.queryUrl, authorization: 'Bearer s3cret', tokens: ['abc', 'def'] }]);
    expect(hits).toEqual([
      { token: 'abc', protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: new Date('2026-01-01T00:00:00.000Z') },
      { token: 'def', protocol: 'dns', callerSourceIp: '198.51.100.53', observedAt: new Date('2026-01-01T00:00:00.000Z') },
    ]);
  });

  it('throws when the query api refuses, so a mid-drain failure is never read as "no callbacks"', async () => {
    const api = stubQueryApi(() => [], 'other-secret');
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    await expect(client.poll(['abc'])).rejects.toThrow(/401/);
  });

  it('drops malformed hits from the api rather than trusting them', async () => {
    const api = stubQueryApi(() => [
      { token: 'abc', protocol: 'gopher' as 'dns', callerSourceIp: '1.2.3.4', observedAt: '2026-01-01T00:00:00Z' },
      { token: 'abc', protocol: 'http', callerSourceIp: '1.2.3.4', observedAt: 'not a date' },
      { token: 'abc', protocol: 'http', callerSourceIp: '1.2.3.4', observedAt: '2026-01-01T00:00:00Z' },
    ]);
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    expect(await client.poll(['abc'])).toHaveLength(1);
  });

  it('self-test passes once colossus fetches its own token url and the listener reports it, learning only http egress', async () => {
    let fetchedByColossus: string | null = null;
    const api = stubQueryApi((tokens) =>
      fetchedByColossus === null
        ? []
        : tokens.flatMap((token) => [
            // The DNS caller is a shared resolver, never Colossus's own egress.
            { token, protocol: 'dns' as const, callerSourceIp: '8.8.8.8', observedAt: '2026-01-01T00:00:00Z' },
            { token, protocol: 'http' as const, callerSourceIp: '192.0.2.10', observedAt: '2026-01-01T00:00:01Z' },
          ]),
    );
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    const result = await client.selfTest(async (url) => {
      fetchedByColossus = url;
      return { body: '', headers: new Headers() };
    });

    expect(fetchedByColossus).toMatch(/^http:\/\/[a-z0-9]{20}\.oast\.example\.net\/$/);
    expect(result).toEqual({ ok: true, ownEgressIps: ['192.0.2.10'] });
  });

  it('self-test fails with a reason when the http callback never arrives', async () => {
    const api = stubQueryApi(() => []);
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    const result = await client.selfTest(async () => ({ body: '', headers: new Headers() }));

    expect(result).toEqual({ ok: false, reason: 'no http callback for the self-test token after 3 polls' });
  });

  it('self-test fails with a reason when the query api rejects the secret', async () => {
    const api = stubQueryApi(() => [], 'other-secret');
    const client = makeHttpCollaboratorClient({ ...config, fetchImpl: api.fetchImpl });

    const result = await client.selfTest(async () => ({ body: '', headers: new Headers() }));

    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/query api.*401/);
  });
});

describe('collaboratorFromEnv', () => {
  const full = {
    COLLABORATOR_BASE_DOMAIN: 'oast.example.net',
    COLLABORATOR_QUERY_URL: 'https://listener.internal:8443/hits',
    COLLABORATOR_SECRET: 's3cret',
  };

  it('builds a client when all three settings are present', () => {
    const result = collaboratorFromEnv(full);
    expect(result.client?.mint().url).toMatch(/\.oast\.example\.net\/$/);
    expect(result.warning).toBeNull();
  });

  it('is absent, silently, when none are set', () => {
    expect(collaboratorFromEnv({})).toEqual({ client: null, warning: null });
  });

  it('is absent with a warning naming what is missing when only some are set', () => {
    const result = collaboratorFromEnv({ ...full, COLLABORATOR_SECRET: undefined });
    expect(result.client).toBeNull();
    expect(result.warning).toMatch(/COLLABORATOR_SECRET/);
  });
});
