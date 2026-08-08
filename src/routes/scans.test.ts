import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { ScannerService, type FetchImpl } from '../services/scanner.js';
import { createScansRoutes } from './scans.js';

function okResponse(): Response {
  return new Response(null, { status: 200 });
}

async function json<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

type ScanBody = { id: number; status: string; targets?: unknown[] };
type ErrorBody = { error: string };

function buildApp(fetchImpl: FetchImpl = vi.fn(async () => okResponse())) {
  const db = createDb(':memory:');
  const service = new ScannerService(db, { fetchImpl });
  return { app: createScansRoutes(service), service };
}

describe('POST /scans', () => {
  it('returns 201 with an id and pending status for a valid submission', async () => {
    const { app } = buildApp();

    const res = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://example.com'] }),
    });

    expect(res.status).toBe(201);
    const body = await json<ScanBody>(res);
    expect(body.id).toEqual(expect.any(Number));
    expect(body.status).toBe('pending');
  });

  it('returns 400 when urls exceeds 100', async () => {
    const { app } = buildApp();
    const urls = Array.from({ length: 101 }, (_, i) => `https://example.com/${i}`);

    const res = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls }),
    });

    expect(res.status).toBe(400);
    const body = await json<ErrorBody>(res);
    expect(body.error).toEqual(expect.any(String));
  });

  it('returns 400 when the body has no urls array', async () => {
    const { app } = buildApp();

    const res = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'oops' }),
    });

    expect(res.status).toBe(400);
  });
});

describe('GET /scans', () => {
  it('lists previously created scans, newest first', async () => {
    const { app } = buildApp();

    await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://a.example.com'] }),
    });
    await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://b.example.com'] }),
    });

    const res = await app.request('/scans');
    expect(res.status).toBe(200);
    const body = await json<ScanBody[]>(res);
    expect(body).toHaveLength(2);
    expect(body[0]?.id).toBeGreaterThan(body[1]?.id ?? 0);
  });
});

describe('GET /scans/:id', () => {
  it('returns the full scan with nested targets', async () => {
    const { app } = buildApp();
    const created = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://example.com'] }),
    });
    const { id } = await json<ScanBody>(created);

    const res = await app.request(`/scans/${id}`);
    expect(res.status).toBe(200);
    const body = await json<ScanBody>(res);
    expect(body.id).toBe(id);
    expect(Array.isArray(body.targets)).toBe(true);
  });

  it('returns 404 for an id that does not exist', async () => {
    const { app } = buildApp();
    const res = await app.request('/scans/999');
    expect(res.status).toBe(404);
  });

  it('returns 400 for a non-numeric id', async () => {
    const { app } = buildApp();
    const res = await app.request('/scans/not-a-number');
    expect(res.status).toBe(400);
  });
});
