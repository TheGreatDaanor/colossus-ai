import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { ScannerService, type FetchImpl } from '../services/scanner.js';
import { ProgramsService } from '../services/programs.js';
import { createDashboardRoutes } from './dashboard.js';

function okResponse(): Response {
  return new Response(null, { status: 200 });
}

function buildApp(fetchImpl: FetchImpl = vi.fn(async () => okResponse())) {
  const db = createDb(':memory:');
  const service = new ScannerService(db, { fetchImpl });
  return { app: createDashboardRoutes(service), service };
}

describe('GET /dashboard', () => {
  it('lists a submitted scan by name and status', async () => {
    const neverResolves: FetchImpl = () => new Promise(() => {});
    const { app, service } = buildApp(neverResolves);
    await service.startScan(['https://example.com'], { name: 'my scan' });

    const res = await app.request('/dashboard');
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).toContain('my scan');
    expect(html).toMatch(/pending|running/);
  });
});

describe('GET /dashboard/scans/:id', () => {
  it('marks which targets the operator submitted and which came from the inventory', async () => {
    const db = createDb(':memory:');
    const programsService = new ProgramsService(db, {
      enumerationImpl: {
        enumerate: async () => [{ hostname: 'a.example.com', source: 'ct-log' as const }],
        resolveEndpoint: async (hostname: string) => `https://${hostname}`,
      },
    });
    const program = await programsService.createProgram({ url: 'https://example.com' });
    for (const entry of program.scopeEntries) await programsService.confirmScopeEntry(program.id, entry.id);
    await programsService.enumerateProgram(program.id);
    const service = new ScannerService(db, { fetchImpl: () => new Promise(() => {}), programsService });
    const app = createDashboardRoutes(service);
    const scan = await service.startScan(['https://submitted.example.com'], { programId: program.id });

    const html = await (await app.request(`/dashboard/scans/${scan.id}`)).text();

    expect(html).toMatch(/https:\/\/submitted\.example\.com<\/td>\s*<td>submitted<\/td>/);
    expect(html).toMatch(/https:\/\/a\.example\.com<\/td>\s*<td>inventory<\/td>/);
  });

  it('renders per-target raw data', async () => {
    const { app, service } = buildApp();
    const scan = await service.startScan(['https://example.com']);
    await vi.waitFor(async () => {
      const s = await service.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

    const res = await app.request(`/dashboard/scans/${scan.id}`);
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).toContain('https://example.com');
    expect(html).toContain('ok');
  });

  it('returns 404 for an unknown scan id', async () => {
    const { app } = buildApp();
    const res = await app.request('/dashboard/scans/999');
    expect(res.status).toBe(404);
  });

  it('escapes HTML in submitted URLs instead of rendering it raw', async () => {
    const { app, service } = buildApp();
    const scan = await service.startScan(['https://example.com/<script>alert(1)</script>']);

    const res = await app.request(`/dashboard/scans/${scan.id}`);
    const html = await res.text();

    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
