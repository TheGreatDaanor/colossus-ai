import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { ScannerService, type FetchImpl, type LlmEnrichImpl } from '../services/scanner.js';
import { createDashboardRoutes } from './dashboard.js';

function okResponse(): Response {
  return new Response(null, { status: 200 });
}

function okLlmEnrichImpl(): LlmEnrichImpl {
  return vi.fn(async (findings) => findings.map(() => ({ explanation: 'why it matters', suggestedFix: 'how to fix it' })));
}

function buildApp(fetchImpl: FetchImpl = vi.fn(async () => okResponse()), llmEnrichImpl: LlmEnrichImpl = okLlmEnrichImpl()) {
  const db = createDb(':memory:');
  const service = new ScannerService(db, { fetchImpl, llmEnrichImpl });
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

  it('renders explanation and suggested_fix inline for a finding, omitting the lines when null', async () => {
    const withHeaders: FetchImpl = async () => okResponse();
    const { app, service } = buildApp(withHeaders);
    const scan = await service.startScan(['https://example.com']);
    await vi.waitFor(async () => {
      const s = await service.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

    const res = await app.request(`/dashboard/scans/${scan.id}`);
    const html = await res.text();

    expect(html).toContain('why it matters');
    expect(html).toContain('how to fix it');
  });

  it('omits explanation/suggested_fix lines entirely when enrichment is null', async () => {
    const failingLlm: LlmEnrichImpl = vi.fn(async () => {
      throw new Error('LLM unavailable');
    });
    const { app, service } = buildApp(vi.fn(async () => okResponse()), failingLlm);
    const scan = await service.startScan(['https://example.com']);
    await vi.waitFor(
      async () => {
        const s = await service.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      { timeout: 5000 },
    );

    const res = await app.request(`/dashboard/scans/${scan.id}`);
    const html = await res.text();

    expect(html).not.toContain('null');
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
