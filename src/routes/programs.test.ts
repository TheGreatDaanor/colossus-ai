import { describe, expect, it } from 'vitest';
import { createDb } from '../db/client.js';
import { ProgramsService } from '../services/programs.js';
import { createProgramsRoutes } from './programs.js';

async function json<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

type ScopeEntryBody = { id: number; list: string; pattern: string; confirmed_at: string | null };
type ProgramBody = { id: number; name: string; scope_entries: ScopeEntryBody[] };
type ClassifyBody = { host: string; status: string };
type ErrorBody = { error: string };

function buildApp() {
  const service = new ProgramsService(createDb(':memory:'));
  return { app: createProgramsRoutes(service), service };
}

function postJson(app: ReturnType<typeof buildApp>['app'], path: string, body: unknown) {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
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
