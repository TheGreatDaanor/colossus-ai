import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import {
  confirmXss,
  generateCanaryPayload,
  makeSstiInjectionClass,
  xssInjectionClass,
} from './active-scanner.js';

// A real loopback server, not `page.route()` — 012 uses that hook as production
// behaviour, and a test that owns it too would fight the code under test.
function startFixture(handler: (q: string) => string): Promise<{ server: Server; origin: string }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(handler(url.searchParams.get('q') ?? ''));
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, origin: `http://127.0.0.1:${port}` });
    });
  });
}

const servers: Server[] = [];
afterAll(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
});

async function fixture(handler: (q: string) => string): Promise<string> {
  const { server, origin } = await startFixture(handler);
  servers.push(server);
  return origin;
}

// A server that accepts the connection but never responds, so navigation times out.
function hangingFixture(): Promise<string> {
  return new Promise((resolve) => {
    const server = createServer(() => {});
    servers.push(server);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

// A server whose only response is a redirect to `location`. Used to prove the
// in-browser SSRF guard aborts a redirect toward a disallowed address.
function redirectingFixture(location: string): Promise<string> {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      res.writeHead(302, { location });
      res.end();
    });
    servers.push(server);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

describe('confirmXss', () => {
  it('confirms execution and captures a screenshot when the page reflects the canary unescaped', async () => {
    const origin = await fixture((q) => `<html><body>${q}</body></html>`);
    const payload = generateCanaryPayload();
    const url = `${origin}/?q=${encodeURIComponent(payload)}`;

    const result = await confirmXss(url, payload);

    expect(result.outcome).toBe('confirmed');
    expect(result.screenshot?.length).toBeGreaterThan(0);
  }, 30_000);

  it('reports not_vulnerable when the page escapes the reflected payload', async () => {
    const origin = await fixture(
      (q) => `<html><body>${q.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</body></html>`,
    );
    const payload = generateCanaryPayload();
    const url = `${origin}/?q=${encodeURIComponent(payload)}`;

    await expect(confirmXss(url, payload)).resolves.toEqual({ outcome: 'not_vulnerable' });
  }, 30_000);

  it('reports unavailable, not not_vulnerable, when navigation times out', async () => {
    const origin = await hangingFixture();
    const payload = generateCanaryPayload();
    const url = `${origin}/?q=${encodeURIComponent(payload)}`;

    const result = await confirmXss(url, payload, { navigationTimeoutMs: 500 });
    expect(result.outcome).toBe('unavailable');
  }, 30_000);

  it('aborts a redirect toward a disallowed address and reports why', async () => {
    const origin = await redirectingFixture('http://169.254.169.254/latest/meta-data/');
    const payload = generateCanaryPayload();
    const url = `${origin}/?q=${encodeURIComponent(payload)}`;

    const result = await confirmXss(url, payload, { navigationTimeoutMs: 3000 });

    expect(result.outcome).toBe('unavailable');
    expect(result.error).toContain('169.254.169.254');
    expect(result.error).toMatch(/disallowed|blocked/i);
  }, 30_000);
});

describe('xssInjectionClass', () => {
  it('reports the xss finding category', () => {
    expect(xssInjectionClass.category).toBe('xss');
  });

  it('enumerates one injection point per query parameter behind the interface', () => {
    const points = xssInjectionClass.enumerate(new URL('https://example.com/search?q=1&page=2'));

    expect(points.map((p) => p.injectionPoint).sort()).toEqual(['page', 'q']);
    expect(points[0]?.payload).not.toEqual(points[1]?.payload);
  });

  it('confirms execution through the browser and captures a screenshot for a reflected canary', async () => {
    const origin = await fixture((q) => `<html><body>${q}</body></html>`);
    const [point] = xssInjectionClass.enumerate(new URL(`${origin}/?q=test`));

    const result = await xssInjectionClass.confirm(point!);

    expect(result.outcome).toBe('confirmed');
    expect(result.screenshot?.length).toBeGreaterThan(0);
  }, 30_000);
});

describe('sstiInjectionClass', () => {
  // A plain (unguarded) fetch: the SSTI class fetches through an injected fetch so
  // loopback fixtures aren't rejected by the SSRF guard the real default enforces.
  const fetchText = async (url: string): Promise<string> => (await fetch(url)).text();

  it('reports the ssti finding category', () => {
    expect(makeSstiInjectionClass(fetchText).category).toBe('ssti');
  });

  it('enumerates one injection point per query parameter with distinct payloads', () => {
    const points = makeSstiInjectionClass(fetchText).enumerate(
      new URL('https://example.com/p?a=1&b=2'),
    );

    expect(points.map((p) => p.injectionPoint).sort()).toEqual(['a', 'b']);
    expect(points[0]?.payload).not.toEqual(points[1]?.payload);
  });

  it('confirms and captures the product as evidence when the engine evaluates the expression', async () => {
    // A vulnerable engine: it evaluates any `<int>*<int>` in the param and reflects
    // the product instead of the literal expression.
    const origin = await fixture((q) => {
      const m = /(\d+)\*(\d+)/.exec(q);
      const body = m ? String(Number(m[1]) * Number(m[2])) : q;
      return `<html><body>result: ${body}</body></html>`;
    });
    const ssti = makeSstiInjectionClass(fetchText);
    const [point] = ssti.enumerate(new URL(`${origin}/?q=seed`));

    const result = await ssti.confirm(point!);

    const m = /(\d+)\*(\d+)/.exec(point!.payload)!;
    const product = String(Number(m[1]) * Number(m[2]));
    expect(result.outcome).toBe('confirmed');
    expect(result.evidenceSnippet).toContain(product);
  });

  it('reports not_vulnerable when the target echoes the literal expression unchanged', async () => {
    const origin = await fixture((q) => `<html><body>result: ${q}</body></html>`);
    const ssti = makeSstiInjectionClass(fetchText);
    const [point] = ssti.enumerate(new URL(`${origin}/?q=seed`));

    const result = await ssti.confirm(point!);

    expect(result.outcome).toBe('not_vulnerable');
    expect(result.evidenceSnippet).toBeUndefined();
  });
});
