import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import { confirmXss, generateCanaryPayload } from './active-scanner.js';

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
