import { describe, expect, it } from 'vitest';
import { createDb } from '../db/client.js';
import { EnumerationError } from '../services/enumeration.js';
import { ProgramsService, type ProgramsServiceOptions } from '../services/programs.js';
import { createProgramsRoutes } from './programs.js';

async function json<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

type ScopeEntryBody = {
  id: number;
  list: string;
  pattern: string;
  confirmed_at: string | null;
  authorization_notice: string | null;
};
type ProgramBody = { id: number; name: string; scope_entries: ScopeEntryBody[] };
type ClassifyBody = { host: string; status: string };
type ErrorBody = { error: string };
type HostBody = {
  id: number;
  hostname: string;
  source: string;
  scope_status: string;
  is_wildcard: boolean;
  endpoint_url: string | null;
  last_resolved_at: string | null;
  is_dormant: boolean;
};
type HostsBody = { hosts: HostBody[]; enumeration_error: string | null };

function buildApp(options: ProgramsServiceOptions = {}) {
  const service = new ProgramsService(createDb(':memory:'), options);
  return { app: createProgramsRoutes(service), service };
}

function postJson(app: ReturnType<typeof buildApp>['app'], path: string, body: unknown) {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// Creates a program from a URL and confirms its inferred apex through the route,
// so tests of enumeration and the inventory exercise those rather than the
// confirmation gate (issue 033), which has its own tests.
async function createConfirmedProgram(app: ReturnType<typeof buildApp>['app'], url: string): Promise<ProgramBody> {
  const created = await json<ProgramBody>(await postJson(app, '/programs', { url }));
  for (const entry of created.scope_entries) {
    await app.request(`/programs/${created.id}/scope/${entry.id}/confirm`, { method: 'POST' });
  }
  return created;
}

describe('POST /programs', () => {
  it('returns 201 with the apex of the submitted URL seeded in scope', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs', { url: 'https://example.com/x' });

    expect(res.status).toBe(201);
    const body = await json<ProgramBody>(res);
    expect(body.id).toEqual(expect.any(Number));
    expect(body.scope_entries).toEqual([
      expect.objectContaining({ list: 'in', pattern: 'example.com', confirmed_at: null }),
    ]);
  });

  it('creates a named program with an empty scope', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs', { name: 'Acme engagement' });

    expect(res.status).toBe(201);
    const body = await json<ProgramBody>(res);
    expect(body.name).toBe('Acme engagement');
    expect(body.scope_entries).toEqual([]);
  });

  it('returns 400 for a body with neither url nor name', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs', {});

    expect(res.status).toBe(400);
  });

  it('returns 400 for a url that is not http or https', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs', { url: 'ftp://example.com' });

    expect(res.status).toBe(400);
    expect((await json<ErrorBody>(res)).error).toEqual(expect.any(String));
  });

  it('returns 400 for a malformed body', async () => {
    const { app } = buildApp();

    const res = await app.request('/programs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });

    expect(res.status).toBe(400);
  });

  it('returns 400 when a host cap is not a number', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs', { name: 'Acme', passiveHostCap: 'lots' });

    expect(res.status).toBe(400);
  });
});

describe('GET /programs/:id', () => {
  it('returns the program with its scope entries', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    const res = await app.request(`/programs/${created.id}`);

    expect(res.status).toBe(200);
    expect((await json<ProgramBody>(res)).scope_entries).toHaveLength(1);
  });

  it('returns 404 for an unknown program', async () => {
    const { app } = buildApp();

    expect((await app.request('/programs/404')).status).toBe(404);
  });

  it('returns 400 for a non-integer id', async () => {
    const { app } = buildApp();

    expect((await app.request('/programs/abc')).status).toBe(400);
  });
});

describe('POST /programs/:id/scope', () => {
  it('adds a second in-scope apex, putting hosts under both in scope', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com/x' }));

    const res = await postJson(app, `/programs/${created.id}/scope`, { list: 'in', pattern: 'example-shop.com' });

    expect(res.status).toBe(201);
    const classify = async (host: string) =>
      (await json<ClassifyBody>(await app.request(`/programs/${created.id}/classify?host=${host}`))).status;
    expect(await classify('blog.example.com')).toBe('in_scope');
    expect(await classify('checkout.example-shop.com')).toBe('in_scope');
  });

  it('returns 400 for a wildcard on the in-scope list', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { name: 'Acme' }));

    const res = await postJson(app, `/programs/${created.id}/scope`, { list: 'in', pattern: '*.example.com' });

    expect(res.status).toBe(400);
  });

  it('returns 400 for a list that is neither in nor out', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { name: 'Acme' }));

    const res = await postJson(app, `/programs/${created.id}/scope`, { list: 'maybe', pattern: 'example.com' });

    expect(res.status).toBe(400);
  });

  it('returns 400 when adding scope to an unknown program', async () => {
    const { app } = buildApp();

    const res = await postJson(app, '/programs/404/scope', { list: 'in', pattern: 'example.com' });

    expect(res.status).toBe(400);
  });
});

describe('DELETE /programs/:id/scope/:entryId', () => {
  it('removes the entry and leaves the program with an empty scope', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));
    const entry = created.scope_entries[0];
    if (!entry) throw new Error('expected a seeded scope entry');

    const res = await app.request(`/programs/${created.id}/scope/${entry.id}`, { method: 'DELETE' });

    expect(res.status).toBe(204);
    const after = await json<ProgramBody>(await app.request(`/programs/${created.id}`));
    expect(after.scope_entries).toEqual([]);
  });

  it('returns 400 for an entry that does not belong to the program', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    const res = await app.request(`/programs/${created.id}/scope/9999`, { method: 'DELETE' });

    expect(res.status).toBe(400);
  });
});

describe('POST /programs/:id/scope/:entryId/confirm', () => {
  it('confirms an inferred entry so enumeration may run against it', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));
    const entry = created.scope_entries[0];
    if (!entry) throw new Error('expected a seeded scope entry');
    expect(entry.confirmed_at).toBeNull();

    const res = await app.request(`/programs/${created.id}/scope/${entry.id}/confirm`, { method: 'POST' });

    expect(res.status).toBe(200);
    expect((await json<ScopeEntryBody>(res)).confirmed_at).not.toBeNull();
    const after = await json<ProgramBody>(await app.request(`/programs/${created.id}`));
    expect(after.scope_entries[0]?.confirmed_at).not.toBeNull();
  });

  it('returns 400 for an entry that does not belong to the program', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    const res = await app.request(`/programs/${created.id}/scope/9999/confirm`, { method: 'POST' });

    expect(res.status).toBe(400);
  });

  it('spells out that confirming widens scope from one host to the whole domain', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://blog.example.com/x' }));
    const entry = created.scope_entries[0];
    if (!entry) throw new Error('expected a seeded scope entry');

    // An unconfirmed inferred entry carries the authorization it is asking for,
    // naming the whole domain — not the one host that was submitted.
    expect(entry.authorization_notice).toContain('example.com');
    expect(entry.authorization_notice).not.toBeNull();

    const confirmed = await json<ScopeEntryBody>(
      await app.request(`/programs/${created.id}/scope/${entry.id}/confirm`, { method: 'POST' }),
    );
    // Once confirmed there is nothing left to authorize, so the notice is gone.
    expect(confirmed.authorization_notice).toBeNull();
  });

  it('carries no authorization notice on an entry the operator typed', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { name: 'Acme' }));
    const added = await json<ScopeEntryBody>(
      await postJson(app, `/programs/${created.id}/scope`, { list: 'in', pattern: 'example.com' }),
    );

    expect(added.authorization_notice).toBeNull();
  });
});

describe('GET /programs/:id/classify', () => {
  it('reports an excluded subtree as out_of_scope even under an in-scope apex', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com/x' }));
    await postJson(app, `/programs/${created.id}/scope`, { list: 'out', pattern: '*.internal.example.com' });

    const res = await app.request(`/programs/${created.id}/classify?host=vpn.internal.example.com`);

    expect(res.status).toBe(200);
    expect(await json<ClassifyBody>(res)).toEqual({ host: 'vpn.internal.example.com', status: 'out_of_scope' });
  });

  it('reports a host matching neither list as unscoped', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    const res = await app.request(`/programs/${created.id}/classify?host=example.org`);

    expect((await json<ClassifyBody>(res)).status).toBe('unscoped');
  });

  it('returns 400 when the host query parameter is missing', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    expect((await app.request(`/programs/${created.id}/classify`)).status).toBe(400);
  });

  it('returns 404 when classifying against an unknown program', async () => {
    const { app } = buildApp();

    expect((await app.request('/programs/404/classify?host=example.com')).status).toBe(404);
  });
});

describe('POST /programs/:id/enumerate', () => {
  it('returns the hosts found, each with its scope status', async () => {
    const { app } = buildApp({
      enumerationImpl: {
        enumerate: async () => [
          { hostname: 'blog.example.com', source: 'ct-log' as const },
          { hostname: 'partner.example.org', source: 'ct-log' as const },
        ],
      },
    });
    const created = await createConfirmedProgram(app, 'https://example.com');

    const res = await app.request(`/programs/${created.id}/enumerate`, { method: 'POST' });

    expect(res.status).toBe(200);
    const body = await json<HostsBody>(res);
    expect(body.hosts).toEqual([
      expect.objectContaining({ hostname: 'blog.example.com', scope_status: 'in_scope', source: 'ct-log' }),
      expect.objectContaining({ hostname: 'partner.example.org', scope_status: 'unscoped' }),
    ]);
  });

  it('returns the existing inventory and reports the error when the CT source fails', async () => {
    const { app, service } = buildApp({
      enumerationImpl: {
        enumerate: async () => {
          throw new EnumerationError('crt.sh: 502 Bad Gateway');
        },
      },
    });
    const created = await createConfirmedProgram(app, 'https://example.com');
    await service.recordHosts(created.id, [{ hostname: 'known.example.com', source: 'ct-log' }]);

    const res = await app.request(`/programs/${created.id}/enumerate`, { method: 'POST' });

    expect(res.status).toBe(200);
    const body = await json<HostsBody>(res);
    expect(body.hosts.map((h) => h.hostname)).toEqual(['known.example.com']);
    expect(body.enumeration_error).toContain('502');
  });

  it('returns 404 for an unknown program', async () => {
    const { app } = buildApp({ enumerationImpl: { enumerate: async () => [] } });

    expect((await app.request('/programs/404/enumerate', { method: 'POST' })).status).toBe(404);
  });
});

describe('GET /programs/:id/hosts', () => {
  it('lists the recorded inventory with scope status', async () => {
    const { app, service } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));
    await service.recordHosts(created.id, [{ hostname: 'blog.example.com', source: 'ct-log' }]);

    const res = await app.request(`/programs/${created.id}/hosts`);

    expect(res.status).toBe(200);
    const body = await json<HostsBody>(res);
    expect(body.hosts).toEqual([
      expect.objectContaining({ hostname: 'blog.example.com', scope_status: 'in_scope', source: 'ct-log' }),
    ]);
  });

  it('marks wildcard hosts, and lists no host the wildcard apex only implied', async () => {
    const { app, service } = buildApp({
      // A wildcard apex: the `*.` identity is recorded against the apex, and the
      // host it merely implied is not in the inventory at all.
      enumerationImpl: {
        enumerate: async () => [
          { hostname: 'example.com', source: 'ct-log', isWildcard: true },
          { hostname: 'blog.example.com', source: 'ct-log' },
        ],
      },
    });
    const created = await createConfirmedProgram(app, 'https://example.com');
    await service.enumerateProgram(created.id);

    const body = await json<HostsBody>(await app.request(`/programs/${created.id}/hosts`));

    expect(body.hosts.map((h) => [h.hostname, h.is_wildcard])).toEqual([
      ['blog.example.com', false],
      ['example.com', true],
    ]);
  });

  it('shows the endpoint each host answers on, and marks a host that has gone dark', async () => {
    let answers = true;
    const { app, service } = buildApp({
      enumerationImpl: {
        enumerate: async () => [
          { hostname: 'blog.example.com', source: 'ct-log' as const },
          { hostname: 'legacy.example.com', source: 'ct-log' as const },
        ],
        resolveEndpoint: async (hostname: string) => {
          if (hostname === 'legacy.example.com') return `http://${hostname}`;
          return answers ? `https://${hostname}` : null;
        },
      },
    });
    const created = await createConfirmedProgram(app, 'https://example.com');
    await service.enumerateProgram(created.id);
    answers = false;
    await service.enumerateProgram(created.id);
    await service.enumerateProgram(created.id);
    await service.enumerateProgram(created.id);

    const body = await json<HostsBody>(await app.request(`/programs/${created.id}/hosts`));

    expect(body.hosts.map((h) => [h.hostname, h.endpoint_url, h.is_dormant])).toEqual([
      ['blog.example.com', 'https://blog.example.com', true],
      ['legacy.example.com', 'http://legacy.example.com', false],
    ]);
    expect(body.hosts[0]?.last_resolved_at).not.toBeNull();
  });

  it('returns an empty list for a program that has never been enumerated', async () => {
    const { app } = buildApp();
    const created = await json<ProgramBody>(await postJson(app, '/programs', { url: 'https://example.com' }));

    expect((await json<HostsBody>(await app.request(`/programs/${created.id}/hosts`))).hosts).toEqual([]);
  });

  it('returns 404 for an unknown program', async () => {
    const { app } = buildApp();

    expect((await app.request('/programs/404/hosts')).status).toBe(404);
  });
});
