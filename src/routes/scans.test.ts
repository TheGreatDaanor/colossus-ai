import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { ScannerService, type FetchImpl, type TlsCheckImpl } from '../services/scanner.js';
import { createScansRoutes } from './scans.js';

function okResponse(): Response {
  return new Response(null, { status: 200 });
}

async function json<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

type ScanBody = {
  id: number;
  status: string;
  targets?: { findings: unknown[] }[];
  findings_by_severity?: Record<string, number>;
};
type ErrorBody = { error: string };

// Faked for the same reason as in scanner.test.ts: an un-injected TLS check opens a
// real socket for https targets, which is slow, offline-hostile, and lets a cert
// nearing expiry silently add findings to assertions that aren't about TLS.
function okTlsCheckImpl(): TlsCheckImpl {
  return vi.fn(async () => ({ version: 'TLSv1.3', certExpiresAt: new Date('2099-01-01T00:00:00Z') }));
}

function buildApp(fetchImpl: FetchImpl = vi.fn(async () => okResponse())) {
  const db = createDb(':memory:');
  const service = new ScannerService(db, { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
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

  it('returns 400 when mode is "active" without confirmAuthorized', async () => {
    const { app } = buildApp();

    const res = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://example.com'], mode: 'active' }),
    });

    expect(res.status).toBe(400);
    const body = await json<ErrorBody>(res);
    expect(body.error).toEqual(expect.any(String));
  });

  it('accepts mode: "active" with confirmAuthorized: true and reports mode on the created scan', async () => {
    const { app } = buildApp();

    const res = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        urls: ['https://example.com'],
        mode: 'active',
        confirmAuthorized: true,
        authorizationNote: 'own domain',
      }),
    });

    expect(res.status).toBe(201);
    const body = await json<ScanBody & { mode: string }>(res);
    expect(body.mode).toBe('active');
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

  it('exposes the severity summary under the snake_case findings_by_severity key', async () => {
    // The exact per-severity numbers are the scanner's contract and are pinned in
    // scanner.test.ts. The route's job is the rename, so assert the block is present,
    // snake_case, complete, and actually totals the findings in the same payload —
    // that catches a dropped or all-zero summary without re-testing header rules.
    const { app } = buildApp(
      vi.fn(async () => new Response(null, { status: 200, headers: { 'set-cookie': 'session=abc123' } })),
    );
    const created = await app.request('/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ urls: ['https://example.com'] }),
    });
    const { id } = await json<ScanBody>(created);

    const body = await vi.waitFor(async () => {
      const res = await app.request(`/scans/${id}`);
      const b = await json<ScanBody>(res);
      if (b.status !== 'completed') throw new Error('not yet completed');
      return b;
    }, { timeout: 5000, interval: 25 });

    const summary = body.findings_by_severity ?? {};
    expect(Object.keys(summary).sort()).toEqual(['critical', 'high', 'info', 'low', 'medium']);

    const totalFindings = (body.targets ?? []).reduce((n, t) => n + t.findings.length, 0);
    expect(totalFindings).toBeGreaterThan(0);
    expect(Object.values(summary).reduce((a, b) => a + b, 0)).toBe(totalFindings);
    expect(body).not.toHaveProperty('findingsBySeverity');
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
