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
    await vi.waitFor(
      async () => {
        const s = await service.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      // A scan finishes on a background task; the 1s default budget is a flake
      // source on a loaded machine.
      { timeout: 15_000 },
    );

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

describe('GET /dashboard/scans/:id — SSRF report surface', () => {
  const baseTarget = {
    id: 1,
    scanId: 1,
    url: 'https://t.example.com/?url=x',
    status: 'ok',
    statusCode: 200,
    responseHeaders: null,
    responseTimeMs: 10,
    tlsVersion: null,
    tlsCertExpiresAt: null,
    redirectLocation: null,
    injectionAttempts: null,
    error: null,
    discoveredFrom: null,
    enumeratedHostId: null,
  };
  const baseFinding = {
    id: 1,
    scanTargetId: 1,
    category: 'ssrf',
    severity: 'high',
    confidence: 'definitive',
    cveId: null,
    explanation: null,
    suggestedFix: null,
    injectionPoint: 'url',
    payload: 'http://tok.collab.example/',
    evidencePath: null,
    evidenceSnippet: null,
    structuredEvidence: null,
    accessControlEvidence: null,
  };

  function appFor(target: Record<string, unknown>) {
    const service = {
      getScan: async () => ({ id: 1, name: 'ssrf scan', status: 'completed', targets: [target] }),
    } as unknown as ScannerService;
    return createDashboardRoutes(service);
  }

  async function render(target: Record<string, unknown>): Promise<string> {
    return (await appFor(target).request('/dashboard/scans/1')).text();
  }

  it('renders ssrf proof as labeled fields instead of raw JSON', async () => {
    const evidence = {
      kind: 'ssrf',
      url: 'https://t.example.com/?url=x',
      param: 'url',
      tier: 'oob',
      protocols: ['dns', 'http'],
      callerSourceIp: '203.0.113.7',
      observedAt: '2026-11-24T10:00:00.000Z',
      internalRead: 'not-demonstrated',
    };
    const html = await render({
      ...baseTarget,
      findings: [{ ...baseFinding, structuredEvidence: JSON.stringify(evidence) }],
    });

    expect(html).not.toContain('&quot;kind&quot;');
    expect(html).toMatch(/<dt>param<\/dt><dd>url<\/dd>/);
    expect(html).toMatch(/<dt>protocols<\/dt><dd>dns, http<\/dd>/);
    expect(html).toMatch(/<dt>caller egress IP<\/dt><dd>203\.0\.113\.7<\/dd>/);
    expect(html).toMatch(/<dt>tier<\/dt><dd>oob<\/dd>/);
    expect(html).toContain('metadata read: not demonstrated');
  });

  it('shows the matched signature on an internal-read finding and omits absent fields', async () => {
    const evidence = {
      kind: 'ssrf',
      url: 'https://t.example.com/?url=x',
      param: 'url',
      tier: 'internal-read',
      protocols: [],
      matchedSignature: 'aws-imdsv1-metadata-listing',
    };
    const html = await render({
      ...baseTarget,
      findings: [{ ...baseFinding, severity: 'critical', structuredEvidence: JSON.stringify(evidence) }],
    });

    expect(html).toMatch(/<dt>matched signature<\/dt><dd>aws-imdsv1-metadata-listing<\/dd>/);
    expect(html).not.toContain('caller egress IP');
    expect(html).not.toContain('metadata read: not demonstrated');
  });

  it('shows a per-parameter not-tested indicator with its reason when SSRF was unavailable', async () => {
    const html = await render({
      ...baseTarget,
      injectionAttempts: [
        { check: 'xss', injectionPoint: 'q', payload: 'p', outcome: 'unavailable', error: 'browser down' },
        { check: 'ssrf', phase: 'oob', injectionPoint: 'url', payload: '', outcome: 'unavailable', error: 'collaborator-not-configured' },
        { check: 'ssrf', phase: 'oob', injectionPoint: 'next', payload: '', outcome: 'unavailable' },
      ],
      findings: [],
    });

    expect(html).toContain('SSRF: not tested (collaborator-not-configured) — param url');
    expect(html).toContain('SSRF: not tested (unknown reason) — param next');
    expect(html).not.toContain('browser down');
  });

  it('summarises untested SSRF params at the top of the scan, grouped by reason', async () => {
    const unavailable = (param: string, error?: string) => ({
      check: 'ssrf', phase: 'oob', injectionPoint: param, payload: '', outcome: 'unavailable', ...(error ? { error } : {}),
    });
    const service = {
      getScan: async () => ({
        id: 1,
        name: 'ssrf scan',
        status: 'completed',
        targets: [
          { ...baseTarget, id: 1, injectionAttempts: [unavailable('url', 'collaborator-not-configured'), unavailable('next', 'collaborator-not-configured')], findings: [] },
          { ...baseTarget, id: 2, injectionAttempts: [unavailable('dest', 'collaborator-unreachable-mid-drain')], findings: [] },
        ],
      }),
    } as unknown as ScannerService;

    const html = await (await createDashboardRoutes(service).request('/dashboard/scans/1')).text();
    const summary = html.slice(0, html.indexOf('<table'));

    expect(summary).toContain('SSRF: not tested on 3 parameters across 2 targets');
    expect(summary).toContain('collaborator-not-configured: 2');
    expect(summary).toContain('collaborator-unreachable-mid-drain: 1');
  });

  it('does not call a param untested when its internal read confirmed despite a failed drain', async () => {
    const html = await render({
      ...baseTarget,
      injectionAttempts: [
        { check: 'ssrf', phase: 'oob', injectionPoint: 'url', payload: 'p', outcome: 'unavailable', error: 'collaborator-unreachable-mid-drain' },
        { check: 'ssrf', phase: 'internal-read', injectionPoint: 'url', payload: 'm', outcome: 'confirmed' },
      ],
      findings: [],
    });

    expect(html).not.toContain('not tested');
  });

  it('falls back to escaped raw JSON for malformed ssrf evidence instead of failing the page', async () => {
    const res = await appFor({
      ...baseTarget,
      findings: [{ ...baseFinding, structuredEvidence: JSON.stringify({ kind: 'ssrf', tier: 'oob' }) }],
    }).request('/dashboard/scans/1');

    expect(res.status).toBe(200);
    expect(await res.text()).toContain('&quot;kind&quot;:&quot;ssrf&quot;');
  });

  it('shows no not-tested indicator when SSRF ran', async () => {
    const html = await render({
      ...baseTarget,
      injectionAttempts: [{ check: 'ssrf', phase: 'oob', injectionPoint: 'url', payload: 'p', outcome: 'not_vulnerable' }],
      findings: [],
    });

    expect(html).not.toContain('not tested');
  });
});
