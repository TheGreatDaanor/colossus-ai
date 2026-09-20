import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFile, rm } from 'node:fs/promises';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { findings, scans, scanTargets } from '../db/schema.js';
import {
  ScannerService,
  ScanValidationError,
  isDisallowedAddress,
  defaultOsvCheck,
  type FetchImpl,
  type TlsCheckImpl,
  type OsvCheckImpl,
  type LlmEnrichImpl,
} from './scanner.js';
import { ProgramsService, type CreateProgramOptions } from './programs.js';

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

// A scan completes on a background task, so every assertion about a finished
// scan has to wait for it. `vi.waitFor` defaults to a 1s budget, which a loaded
// machine running the whole suite in parallel can miss on a scan that does real
// async work - the failure is a timeout, not a wrong result, so it surfaces as
// flake. Waiting lives here, with one budget, rather than open-coded per test.
const SCAN_COMPLETION_TIMEOUT_MS = 15_000;

async function completedScan(svc: ScannerService, scanId: number) {
  return await vi.waitFor(
    async () => {
      const s = await svc.getScan(scanId);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    },
    { timeout: SCAN_COMPLETION_TIMEOUT_MS },
  );
}

// A response that trips none of the header checks — used to pin the zero-findings shape.
const FULLY_HARDENED_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'geolocation=()',
};

function okResponse(body: Record<string, string> = { 'x-test': '1' }): Response {
  return new Response(null, { status: 200, headers: body });
}

// Every test above the `detectTlsFindings`/TLS-specific block exercises https
// targets incidentally, not the TLS check itself — inject a fast, deterministic
// stand-in so those tests never open a real socket (per the issue's "no real
// sockets in tests" testing decision) and stay fast/offline-safe.
function okTlsCheckImpl(): TlsCheckImpl {
  return vi.fn(async () => ({ version: 'TLSv1.3', certExpiresAt: new Date('2099-01-01T00:00:00Z') }));
}

describe('ScannerService program scans', () => {
  // A program whose inventory is already enumerated and probed, sharing one
  // database with the scanner under test — the two services meet at the tables.
  async function seedProgram(db: ReturnType<typeof createDb>, hosts: string[], caps: CreateProgramOptions = {}) {
    const programsService = new ProgramsService(db, {
      enumerationImpl: {
        enumerate: async () => hosts.map((hostname) => ({ hostname, source: 'ct-log' as const })),
        resolveEndpoint: async (hostname: string) => `https://${hostname}`,
      },
    });
    const program = await programsService.createProgram({ url: 'https://example.com', ...caps });
    for (const entry of program.scopeEntries) await programsService.confirmScopeEntry(program.id, entry.id);
    await programsService.enumerateProgram(program.id);
    return { programsService, program };
  }

  function buildScanner(db: ReturnType<typeof createDb>, programsService: ProgramsService) {
    return new ScannerService(db, {
      fetchImpl: vi.fn(async () => okResponse()),
      tlsCheckImpl: okTlsCheckImpl(),
      programsService,
    });
  }

  it('resolves targets from the program inventory for hosts the operator never submitted', async () => {
    const db = createDb(':memory:');
    const { programsService, program } = await seedProgram(db, ['a.example.com', 'b.example.com']);
    const svc = buildScanner(db, programsService);

    const scan = await svc.startScan([], { programId: program.id });

    const stored = await svc.getScan(scan.id);
    expect(stored?.targets.map((t) => t.url).sort()).toEqual(['https://a.example.com', 'https://b.example.com']);
  });

  it('scans submitted URLs alongside the inventory, marking which targets came from the inventory', async () => {
    const db = createDb(':memory:');
    const { programsService, program } = await seedProgram(db, ['a.example.com']);
    const svc = buildScanner(db, programsService);

    const scan = await svc.startScan(['https://submitted.example.com'], { programId: program.id });

    const stored = await svc.getScan(scan.id);
    const byUrl = new Map(stored?.targets.map((t) => [t.url, t.enumeratedHostId]));
    expect(byUrl.get('https://submitted.example.com')).toBeNull();
    expect(byUrl.get('https://a.example.com')).toEqual(expect.any(Number));
  });

  it('caps a run at the program override rather than the mode default', async () => {
    const db = createDb(':memory:');
    const hosts = ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'];
    const { programsService, program } = await seedProgram(db, hosts, { passiveHostCap: 2 });
    const svc = buildScanner(db, programsService);

    const scan = await svc.startScan([], { programId: program.id });

    expect((await svc.getScan(scan.id))?.targets).toHaveLength(2);
  });

  it('reaches the hosts a capped earlier run left behind on the next run', async () => {
    const db = createDb(':memory:');
    const hosts = ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'];
    const { programsService, program } = await seedProgram(db, hosts, { passiveHostCap: 2 });
    const svc = buildScanner(db, programsService);
    await svc.startScan([], { programId: program.id });

    const second = await svc.startScan([], { programId: program.id });

    const stored = await svc.getScan(second.id);
    expect(stored?.targets.map((t) => t.url).sort()).toEqual(['https://c.example.com', 'https://d.example.com']);
  });

  it('fails a program scan that has no reachable hosts and no submitted URLs', async () => {
    const db = createDb(':memory:');
    const { programsService, program } = await seedProgram(db, []);
    const svc = buildScanner(db, programsService);

    const scan = await svc.startScan([], { programId: program.id });

    expect(scan.status).toBe('failed');
    expect(scan.error).toBe('no targets to scan');
  });

  it('leaves a scan with no program drawing only on the URLs the operator submitted', async () => {
    const db = createDb(':memory:');
    const { programsService } = await seedProgram(db, ['a.example.com']);
    const svc = buildScanner(db, programsService);

    const scan = await svc.startScan(['https://submitted.example.com']);

    expect(scan.programId).toBeNull();
    expect((await svc.getScan(scan.id))?.targets.map((t) => t.url)).toEqual(['https://submitted.example.com']);
  });

  it('rejects a scan against a program that does not exist', async () => {
    const db = createDb(':memory:');
    const { programsService } = await seedProgram(db, []);
    const svc = buildScanner(db, programsService);

    await expect(svc.startScan([], { programId: 404 })).rejects.toThrow(ScanValidationError);
  });
});

describe('ScannerService scope-aware crawl discovery', () => {
  const HTML_HEADERS = { 'content-type': 'text/html; charset=utf-8' };

  // A page that links out to one in-scope host, one excluded host and one host the
  // program never mentioned. Only the first is authorized to be fetched.
  const ROOT_HTML = `
    <a href="https://blog.example.com/post">In scope</a>
    <a href="https://secret.example.com/x">Out of scope</a>
    <a href="https://evil.example/steal">Unscoped</a>
  `;

  async function seedScopedProgram(db: ReturnType<typeof createDb>) {
    const programsService = new ProgramsService(db, {
      enumerationImpl: {
        enumerate: async () => [],
        resolveEndpoint: async (hostname: string) => `https://${hostname}`,
      },
    });
    const program = await programsService.createProgram({ url: 'https://example.com' });
    for (const entry of program.scopeEntries) await programsService.confirmScopeEntry(program.id, entry.id);
    await programsService.addScopeEntry(program.id, { list: 'out', pattern: 'secret.example.com' });
    return { programsService, program };
  }

  async function runProgramScan(db: ReturnType<typeof createDb>, programsService: ProgramsService, programId: number) {
    const fetchImpl: FetchImpl = vi.fn(async (url) =>
      String(url) === 'https://example.com/'
        ? new Response(ROOT_HTML, { status: 200, headers: HTML_HEADERS })
        : new Response('', { status: 200, headers: HTML_HEADERS }),
    );
    const svc = new ScannerService(db, { fetchImpl, tlsCheckImpl: okTlsCheckImpl(), programsService });
    const scan = await svc.startScan(['https://example.com/'], { programId });
    const completed = await completedScan(svc, scan.id);
    return { completed, fetchImpl };
  }

  it('follows a link to an in-scope host and leaves out-of-scope and unscoped links alone', async () => {
    const db = createDb(':memory:');
    const { programsService, program } = await seedScopedProgram(db);

    const { completed, fetchImpl } = await runProgramScan(db, programsService, program.id);

    expect(completed.targets.map((t) => t.url).sort()).toEqual([
      'https://blog.example.com/post',
      'https://example.com/',
    ]);
    const fetchedHosts = vi.mocked(fetchImpl).mock.calls.map(([url]) => new URL(String(url)).hostname);
    expect(fetchedHosts).not.toContain('secret.example.com');
    expect(fetchedHosts).not.toContain('evil.example');
  });

  it('records every crawled host in the inventory with source `crawl`', async () => {
    const db = createDb(':memory:');
    const { programsService, program } = await seedScopedProgram(db);

    await runProgramScan(db, programsService, program.id);

    const inventory = await programsService.listHosts(program.id);
    expect(inventory.map((h) => [h.hostname, h.source, h.scopeStatus]).sort()).toEqual([
      ['blog.example.com', 'crawl', 'in_scope'],
      ['evil.example', 'crawl', 'unscoped'],
      ['secret.example.com', 'crawl', 'out_of_scope'],
    ]);
  });

  it('keeps the same-origin rule for a scan submitted without a program', async () => {
    const db = createDb(':memory:');
    const fetchImpl: FetchImpl = vi.fn(async (url) =>
      String(url) === 'https://example.com/'
        ? new Response(ROOT_HTML, { status: 200, headers: HTML_HEADERS })
        : new Response('', { status: 200, headers: HTML_HEADERS }),
    );
    const svc = new ScannerService(db, { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/']);
    const completed = await completedScan(svc, scan.id);

    expect(completed.targets.map((t) => t.url)).toEqual(['https://example.com/']);
  });
});

describe('ScannerService active mode', () => {
  it('rejects mode: "active" without confirmAuthorized', async () => {
    const svc = new ScannerService(createDb(':memory:'));
    await expect(svc.startScan(['https://example.com'], { mode: 'active' })).rejects.toThrow(ScanValidationError);
  });

  it('rejects mode: "active" with confirmAuthorized: false', async () => {
    const svc = new ScannerService(createDb(':memory:'));
    await expect(
      svc.startScan(['https://example.com'], { mode: 'active', confirmAuthorized: false }),
    ).rejects.toThrow(ScanValidationError);
  });

  it('accepts mode: "active" with confirmAuthorized: true and persists mode/attestation', async () => {
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl: vi.fn(async () => okResponse()) });
    const scan = await svc.startScan(['https://example.com'], {
      mode: 'active',
      confirmAuthorized: true,
      authorizationNote: 'own domain',
    });

    expect(scan.mode).toBe('active');
    expect(scan.confirmAuthorized).toBe(true);
    expect(scan.authorizationNote).toBe('own domain');
  });

  it('defaults to passive mode when mode is omitted', async () => {
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl: vi.fn(async () => okResponse()) });
    const scan = await svc.startScan(['https://example.com']);

    expect(scan.mode).toBe('passive');
    expect(scan.confirmAuthorized).toBeNull();
  });
});

describe('ScannerService User-Agent', () => {
  it('sends the constructor-configured default User-Agent on every fetch', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      defaultUserAgent: 'colossus-scanner/1.0',
    });
    const scan = await svc.startScan(['https://example.com']);

    await completedScan(svc, scan.id);

    expect(fetchImpl).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({ headers: { 'user-agent': 'colossus-scanner/1.0' } }),
    );
  });

  it('overrides the default User-Agent with a per-scan value', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      defaultUserAgent: 'colossus-scanner/1.0',
    });
    const scan = await svc.startScan(['https://example.com'], { userAgent: 'custom-agent/2.0' });

    await completedScan(svc, scan.id);

    expect(fetchImpl).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({ headers: { 'user-agent': 'custom-agent/2.0' } }),
    );
  });

  it('rejects a blank userAgent override rather than scanning unidentified', async () => {
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl: vi.fn(async () => okResponse()),
      tlsCheckImpl: okTlsCheckImpl(),
      defaultUserAgent: 'colossus-scanner/1.0',
    });

    await expect(svc.startScan(['https://example.com'], { userAgent: '   ' })).rejects.toThrow(
      ScanValidationError,
    );
  });
});

describe('ScannerService', () => {
  it('rejects an empty URL list', async () => {
    const svc = new ScannerService(createDb(':memory:'));
    await expect(svc.startScan([])).rejects.toThrow(ScanValidationError);
  });

  it('rejects more than 100 URLs', async () => {
    const svc = new ScannerService(createDb(':memory:'));
    const urls = Array.from({ length: 101 }, (_, i) => `https://example.com/${i}`);
    await expect(svc.startScan(urls)).rejects.toThrow(ScanValidationError);
  });

  it('returns immediately with status pending while a fetch is still in flight', async () => {
    const { promise } = deferred<Response>();
    const fetchImpl: FetchImpl = vi.fn(() => promise);
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });

    const scan = await svc.startScan(['https://example.com']);

    expect(scan.status).toBe('pending');
  });

  it('records raw response data and completes once a fetch succeeds', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse({ 'X-Test': 'yes' }));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    expect(completed.targets).toHaveLength(1);
    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.statusCode).toBe(200);
    expect(target?.responseHeaders).toEqual({ 'x-test': 'yes' });
    expect(target?.responseTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('marks a target unreachable when the fetch rejects', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => {
      throw new Error('connection refused');
    });
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('unreachable');
    expect(target?.responseTimeMs).toBeNull();
  });

  it('marks a target timed-out when the fetch is aborted', async () => {
    const fetchImpl: FetchImpl = vi.fn(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    );
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, timeoutMs: 5 });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('timeout');
    expect(target?.responseTimeMs).toBeNull();
  });

  it('classifies a redirect response as ok with a recorded redirect_location', async () => {
    const fetchImpl: FetchImpl = vi.fn(
      async () => new Response(null, { status: 302, headers: { location: 'https://example.com/new' } }),
    );
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.statusCode).toBe(302);
    expect(target?.redirectLocation).toBe('https://example.com/new');
  });

  it('records a Finding per missing security header and one per missing cookie attribute', async () => {
    const fetchImpl: FetchImpl = vi.fn(
      async () =>
        new Response(null, {
          status: 200,
          headers: { 'set-cookie': 'session=abc123' },
        }),
    );
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings).toHaveLength(9);
    expect(target?.findings.map((f) => f.category).sort()).toEqual(
      [
        'cookie-missing-httponly',
        'cookie-missing-samesite',
        'cookie-missing-secure',
        'missing-csp',
        'missing-hsts',
        'missing-permissions-policy',
        'missing-referrer-policy',
        'missing-x-content-type-options',
        'missing-x-frame-options',
      ].sort(),
    );
    for (const finding of target?.findings ?? []) {
      expect(finding.confidence).toBe('definitive');
    }
  });

  it('counts findings by severity across all targets in the scan', async () => {
    const fetchImpl: FetchImpl = vi.fn(
      async () =>
        new Response(null, {
          status: 200,
          headers: { 'set-cookie': 'session=abc123' },
        }),
    );
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com', 'https://example.org']);

    const completed = await completedScan(svc, scan.id);

    // Both targets get the same response — no security headers, plus a cookie missing
    // all three tracked attributes — which yields nine findings each: 2 high (missing
    // CSP, missing HSTS), 4 medium (missing X-Frame-Options, and one per missing cookie
    // attribute), 3 low (missing X-Content-Type-Options, Referrer-Policy,
    // Permissions-Policy). The summary is therefore exactly double a single target's counts.
    expect(completed.targets).toHaveLength(2);
    expect(completed.findingsBySeverity).toEqual({
      critical: 0,
      high: 4,
      medium: 8,
      low: 6,
      info: 0,
    });
  });

  it('reports all-zero severity counts for a scan with no findings', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    expect(completed.targets.flatMap((t) => t.findings)).toHaveLength(0);
    expect(completed.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it('ignores a stored severity outside the known set instead of poisoning the counts', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const db = createDb(':memory:');
    const svc = new ScannerService(db, { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    // `severity` is `text().$type<FindingSeverity>()` — a compile-time cast with no
    // runtime constraint, so a row can carry a value outside the union. Write one
    // directly to prove the summary stays a valid count block.
    const target = completed.targets[0];
    if (!target) throw new Error('expected a scan target');
    db.insert(findings)
      .values({
        scanTargetId: target.id,
        category: 'from-the-future',
        severity: 'catastrophic' as never,
        confidence: 'definitive',
      })
      .run();
    // `constructor` is the interesting case: it is truthy under `in` because it
    // lives on Object.prototype, so a prototype-chain guard lets it through.
    db.insert(findings)
      .values({
        scanTargetId: target.id,
        category: 'prototype-shaped',
        severity: 'constructor' as never,
        confidence: 'definitive',
      })
      .run();

    const reread = await svc.getScan(scan.id);
    expect(reread?.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it('records tls_version and tls_cert_expires_at on an https target from the TLS check', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const certExpiresAt = new Date('2099-01-01T00:00:00Z');
    const tlsCheckImpl: TlsCheckImpl = vi.fn(async () => ({ version: 'TLSv1.3', certExpiresAt }));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.tlsVersion).toBe('TLSv1.3');
    expect(target?.tlsCertExpiresAt).toEqual(certExpiresAt);
  });

  it('records an outdated-tls Finding for an https target on TLS below 1.2', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const tlsCheckImpl: TlsCheckImpl = vi.fn(async () => ({
      version: 'TLSv1',
      certExpiresAt: new Date('2099-01-01T00:00:00Z'),
    }));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'outdated-tls')).toMatchObject({
      severity: 'high',
      confidence: 'definitive',
    });
  });

  it('records a cert-expiring-soon Finding for an https target with a cert expiring within 30 days', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const soon = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000);
    const tlsCheckImpl: TlsCheckImpl = vi.fn(async () => ({ version: 'TLSv1.3', certExpiresAt: soon }));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'cert-expiring-soon')).toMatchObject({
      severity: 'medium',
      confidence: 'definitive',
    });
  });

  it('records a no-tls Finding for a plain http:// target and skips the TLS check', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const tlsCheckImpl: TlsCheckImpl = vi.fn(async () => ({
      version: 'TLSv1.3',
      certExpiresAt: new Date('2099-01-01T00:00:00Z'),
    }));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl });

    const scan = await svc.startScan(['http://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'no-tls')).toMatchObject({
      severity: 'high',
      confidence: 'definitive',
    });
    expect(target?.tlsVersion).toBeNull();
    expect(tlsCheckImpl).not.toHaveBeenCalled();
  });

  it('leaves TLS fields null and keeps the target ok when the TLS check fails', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const tlsCheckImpl: TlsCheckImpl = vi.fn(async () => {
      throw new Error('handshake failed');
    });
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.tlsVersion).toBeNull();
    expect(target?.findings.find((f) => f.category === 'outdated-tls' || f.category === 'cert-expiring-soon')).toBeUndefined();
  });

  it('gives a target on a private/loopback/link-local/metadata IP an invalid status without fetching it', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });

    const scan = await svc.startScan(['http://127.0.0.1', 'http://169.254.169.254']);

    const completed = await completedScan(svc, scan.id);

    expect(completed.targets).toHaveLength(2);
    for (const target of completed.targets) {
      expect(target.status).toBe('invalid');
      expect(target.error).toBeTruthy();
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('gives a malformed or disallowed-scheme URL an invalid target without fetching it', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });

    const scan = await svc.startScan(['not a url', 'file:///etc/passwd', 'https://good.example.com']);
    const result = await svc.getScan(scan.id);

    const invalidTargets = result?.targets.filter((t) => t.status === 'invalid') ?? [];
    expect(invalidTargets).toHaveLength(2);
    expect(fetchImpl).not.toHaveBeenCalledWith('not a url', expect.anything());
    expect(fetchImpl).not.toHaveBeenCalledWith('file:///etc/passwd', expect.anything());
  });

  it('dedupes exact-string-duplicate URLs into a single target', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });

    const scan = await svc.startScan(['https://example.com', 'https://example.com']);
    const result = await svc.getScan(scan.id);

    expect(result?.targets).toHaveLength(1);
  });

  it('fails the scan immediately when every URL is invalid', async () => {
    const svc = new ScannerService(createDb(':memory:'));

    const scan = await svc.startScan(['not a url', 'file:///etc/passwd']);

    expect(scan.status).toBe('failed');
    expect(scan.completedAt).not.toBeNull();
  });

  it('returns null from getScan for an id that does not exist', async () => {
    const svc = new ScannerService(createDb(':memory:'));
    await expect(svc.getScan(999)).resolves.toBeNull();
  });

  it('lists scans newest first', async () => {
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl: vi.fn(async () => okResponse()),
      tlsCheckImpl: okTlsCheckImpl(),
    });

    const first = await svc.startScan(['https://a.example.com']);
    const second = await svc.startScan(['https://b.example.com']);

    const list = await svc.listScans();

    expect(list.map((s) => s.id)).toEqual([second.id, first.id]);
  });

  it('defaults the scan name to a human-readable timestamp when omitted', async () => {
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl: vi.fn(async () => okResponse()),
      tlsCheckImpl: okTlsCheckImpl(),
    });
    const scan = await svc.startScan(['https://example.com']);
    expect(scan.name).toMatch(/^Scan \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it('records a possible-confidence Finding with a cve_id when the version banner matches an OSV.dev vulnerability', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse({ server: 'nginx/1.18.0' }));
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => ({ cveId: 'CVE-2021-23017' }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')).toMatchObject({
      confidence: 'possible',
      cveId: 'CVE-2021-23017',
    });
  });

  it('does not query OSV.dev a second time for a second target with the identical version banner', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse({ server: 'nginx/1.18.0' }));
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => ({ cveId: 'CVE-2021-23017' }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://a.example.com', 'https://b.example.com']);

    const completed = await completedScan(svc, scan.id);

    for (const target of completed.targets) {
      expect(target.findings.find((f) => f.category === 'known-vulnerability')).toMatchObject({
        cveId: 'CVE-2021-23017',
      });
    }
    expect(osvCheckImpl).toHaveBeenCalledTimes(1);
  });

  it('retries an OSV.dev lookup once before giving up, keeping the target ok with no CVE finding', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse({ server: 'nginx/1.18.0' }));
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => {
      throw new Error('OSV.dev unavailable');
    });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')).toBeUndefined();
    expect(osvCheckImpl).toHaveBeenCalledTimes(2);
  });

  it('recovers a CVE match when the OSV.dev lookup succeeds on retry', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse({ server: 'nginx/1.18.0' }));
    const osvCheckImpl: OsvCheckImpl = vi
      .fn<OsvCheckImpl>()
      .mockRejectedValueOnce(new Error('transient failure'))
      .mockResolvedValueOnce({ cveId: 'CVE-2021-23017' });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')).toMatchObject({
      cveId: 'CVE-2021-23017',
    });
  });

  it('records no known-vulnerability Finding when no version banner is present', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => ({ cveId: 'CVE-2021-23017' }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')).toBeUndefined();
    expect(osvCheckImpl).not.toHaveBeenCalled();
  });

  it('keeps the target ok and still extracts a banner from headers when the robots.txt fetch fails', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url: string) => {
      if (url.endsWith('/robots.txt')) throw new Error('connection refused');
      return okResponse({ server: 'nginx/1.18.0' });
    });
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => ({ cveId: 'CVE-2021-23017' }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')).toMatchObject({
      cveId: 'CVE-2021-23017',
    });
  });

  it('processes at most `concurrency` URLs at once', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const fetchImpl: FetchImpl = vi.fn(async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 10));
      inFlight -= 1;
      return okResponse();
    });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      concurrency: 3,
      tlsCheckImpl: okTlsCheckImpl(),
    });
    const urls = Array.from({ length: 7 }, (_, i) => `https://example.com/${i}`);

    const scan = await svc.startScan(urls);

    await completedScan(svc, scan.id);

    expect(maxInFlight).toBeLessThanOrEqual(3);
  });
});

describe('isDisallowedAddress', () => {
  it('flags IPv4 loopback addresses', () => {
    expect(isDisallowedAddress('127.0.0.1')).toBe(true);
    expect(isDisallowedAddress('127.255.255.255')).toBe(true);
  });

  it('flags IPv4 private ranges', () => {
    expect(isDisallowedAddress('10.0.0.1')).toBe(true);
    expect(isDisallowedAddress('172.16.0.1')).toBe(true);
    expect(isDisallowedAddress('172.31.255.255')).toBe(true);
    expect(isDisallowedAddress('192.168.1.1')).toBe(true);
  });

  it('flags IPv4 link-local addresses, including the cloud metadata address', () => {
    expect(isDisallowedAddress('169.254.169.254')).toBe(true);
    expect(isDisallowedAddress('169.254.0.1')).toBe(true);
  });

  it('allows public IPv4 addresses', () => {
    expect(isDisallowedAddress('8.8.8.8')).toBe(false);
    expect(isDisallowedAddress('93.184.216.34')).toBe(false);
  });

  it('flags the IPv6 loopback address', () => {
    expect(isDisallowedAddress('::1')).toBe(true);
  });

  it('flags IPv6 link-local addresses', () => {
    expect(isDisallowedAddress('fe80::1')).toBe(true);
  });

  it('flags IPv6 unique-local (private) addresses', () => {
    expect(isDisallowedAddress('fd00::1')).toBe(true);
    expect(isDisallowedAddress('fc00::1')).toBe(true);
  });

  it('allows public IPv6 addresses', () => {
    expect(isDisallowedAddress('2606:4700:4700::1111')).toBe(false);
  });

  it('flags IPv4-mapped IPv6 addresses that embed a disallowed IPv4 address', () => {
    expect(isDisallowedAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isDisallowedAddress('::ffff:169.254.169.254')).toBe(true);
  });
});

describe('ScannerService exposed-file probing', () => {
  // Serves a distinct body per path; anything unlisted 404s.
  function pathServer(bodies: Record<string, string>): FetchImpl {
    return vi.fn(async (url: string | URL) => {
      const path = new URL(url).pathname;
      const body = bodies[path];
      if (body === undefined) return new Response('not found', { status: 404 });
      return new Response(body, { status: 200, headers: FULLY_HARDENED_HEADERS });
    }) as unknown as FetchImpl;
  }

  async function categoriesFor(fetchImpl: FetchImpl): Promise<string[]> {
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);
    const completed = await completedScan(svc, scan.id);
    return completed.targets.flatMap((t) => t.findings).map((f) => f.category);
  }

  it('reports an exposed .git directory as critical', async () => {
    const result = await categoriesFor(pathServer({ '/': 'ok', '/.git/HEAD': 'ref: refs/heads/main\n' }));

    expect(result).toContain('exposed-git-directory');
  });

  it('reports an exposed .env file', async () => {
    const result = await categoriesFor(pathServer({ '/': 'ok', '/.env': 'DB_PASSWORD=hunter2\nAPI_KEY=abc\n' }));

    expect(result).toContain('exposed-env-file');
  });

  it('reports an exposed server-status page', async () => {
    const result = await categoriesFor(
      pathServer({ '/': 'ok', '/server-status': '<h1>Apache Server Status for example.com</h1>' }),
    );

    expect(result).toContain('exposed-server-status');
  });

  it('records a present security.txt as an info finding', async () => {
    const result = await categoriesFor(
      pathServer({ '/': 'ok', '/.well-known/security.txt': 'Contact: mailto:security@example.com\n' }),
    );

    expect(result).toContain('security-txt-present');
  });

  it('produces no probe findings when every path returns a 200 HTML shell', async () => {
    const shell = '<!doctype html><html><body><div id="app"></div></body></html>';
    const fetchImpl = vi.fn(async () =>
      new Response(shell, { status: 200, headers: FULLY_HARDENED_HEADERS }),
    ) as unknown as FetchImpl;

    const result = await categoriesFor(fetchImpl);

    expect(result.filter((c) => c.startsWith('exposed-') || c === 'security-txt-present')).toEqual([]);
  });

  it('produces no probe findings when the paths 404', async () => {
    const result = await categoriesFor(pathServer({ '/': 'ok' }));

    expect(result.filter((c) => c.startsWith('exposed-') || c === 'security-txt-present')).toEqual([]);
  });

  it('spends no more than maxExtraRequests beyond the primary fetch per target', async () => {
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200, headers: FULLY_HARDENED_HEADERS }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl: fetchImpl as unknown as FetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      maxExtraRequests: 2,
    });
    const scan = await svc.startScan(['https://example.com']);
    await completedScan(svc, scan.id);

    // 1 primary fetch + exactly 2 extra (robots.txt and probes share the allowance);
    // unbounded, this target would spend 1 + robots + 4 probes = 6.
    expect(fetchImpl.mock.calls.length).toBe(3);
  });

  it('gives each target its own allowance rather than a shared global one', async () => {
    const fetchImpl = vi.fn(async () => new Response('ok', { status: 200, headers: FULLY_HARDENED_HEADERS }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl: fetchImpl as unknown as FetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      maxExtraRequests: 2,
    });
    const scan = await svc.startScan(['https://a.example.com', 'https://b.example.com']);
    await completedScan(svc, scan.id);

    // Two targets, each allowed a primary fetch plus 2 extras: a shared global
    // budget would cap the whole scan at 2 extras and fail this.
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(3);
  });
});

describe('ScannerService weak security headers', () => {
  it('persists weak-header findings with their severities, visible through getScan', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      okResponse({
        ...FULLY_HARDENED_HEADERS,
        'content-security-policy': "default-src 'self' 'unsafe-inline'",
        'strict-transport-security': 'max-age=120',
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
        server: 'nginx/1.18.0',
      }),
    );
    // Stub the OSV check: this test drives a nginx banner but is not about CVE
    // correlation, and defaultOsvCheck now makes a real network call that would
    // exceed the waitFor budget.
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      osvCheckImpl: vi.fn(async () => null),
    });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const bySeverity = new Map(completed.targets.flatMap((t) => t.findings).map((f) => [f.category, f.severity]));

    expect(Object.fromEntries(bySeverity)).toMatchObject({
      'weak-csp-unsafe-inline': 'high',
      'weak-csp-missing-frame-ancestors': 'low',
      'weak-hsts-short-max-age': 'medium',
      'weak-hsts-no-subdomains': 'low',
      'permissive-cors-credentialed': 'high',
      'information-disclosure-header': 'low',
    });
    expect(bySeverity.has('permissive-cors-wildcard')).toBe(false);
  });
});

describe('ScannerService LLM finding enrichment', () => {
  it('populates explanation and suggestedFix on findings from the LLM enrichment call', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi.fn<LlmEnrichImpl>(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.length).toBeGreaterThan(0);
    for (const finding of target?.findings ?? []) {
      expect(finding.explanation).toBe('plain-english explanation');
      expect(finding.suggestedFix).toBe('add the header');
    }
  });

  it('does not call the LLM a second time for an identical finding-set within the same scan', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi.fn<LlmEnrichImpl>(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://a.example.com', 'https://b.example.com']);

    const completed = await completedScan(svc, scan.id);

    for (const target of completed.targets) {
      expect(target.findings.length).toBeGreaterThan(0);
      for (const finding of target.findings) {
        expect(finding.explanation).toBe('plain-english explanation');
      }
    }
    expect(llmEnrichImpl).toHaveBeenCalledTimes(1);
  });

  it('retries the LLM call once before degrading findings to null explanation/suggestedFix', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async () => {
      throw new Error('LLM unavailable');
    });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.findings.length).toBeGreaterThan(0);
    for (const finding of target?.findings ?? []) {
      expect(finding.explanation).toBeNull();
      expect(finding.suggestedFix).toBeNull();
    }
    expect(llmEnrichImpl).toHaveBeenCalledTimes(2);
  });

  it('recovers explanations when the LLM call succeeds on retry', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi
      .fn<LlmEnrichImpl>()
      .mockRejectedValueOnce(new Error('transient failure'))
      .mockImplementationOnce(async (toEnrich) =>
        toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
      );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    for (const finding of target?.findings ?? []) {
      expect(finding.explanation).toBe('plain-english explanation');
    }
  });

  it('does not call the LLM when a target produces no findings', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      okResponse(FULLY_HARDENED_HEADERS),
    );
    const llmEnrichImpl: LlmEnrichImpl = vi.fn<LlmEnrichImpl>(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.length).toBe(0);
    expect(llmEnrichImpl).not.toHaveBeenCalled();
  });

  it('enriches only the findings the LLM actually returns, keyed by id, when the response is a reordered subset', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    // okResponse() with no security headers set produces six missing-header findings,
    // sent to the LLM as f0..f5. This mock returns results for only two of them
    // (f4 and f1), out of order, simulating a truncated/reordered LLM response.
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async () => [
      { id: 'f4', explanation: 'explanation for f4', suggestedFix: 'fix for f4' },
      { id: 'f1', explanation: 'explanation for f1', suggestedFix: 'fix for f1' },
    ]);
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    expect(target?.findings.length).toBe(6);

    const byCategory = new Map(target?.findings.map((f) => [f.category, f]) ?? []);
    // f4 is the 5th pending finding (index 4): missing-referrer-policy.
    expect(byCategory.get('missing-referrer-policy')?.explanation).toBe('explanation for f4');
    expect(byCategory.get('missing-referrer-policy')?.suggestedFix).toBe('fix for f4');
    // f1 is the 2nd pending finding (index 1): missing-hsts.
    expect(byCategory.get('missing-hsts')?.explanation).toBe('explanation for f1');
    expect(byCategory.get('missing-hsts')?.suggestedFix).toBe('fix for f1');

    const enrichedCount = target?.findings.filter((f) => f.explanation !== null).length;
    expect(enrichedCount).toBe(2);
    for (const finding of target?.findings ?? []) {
      if (finding.explanation === null) {
        expect(finding.suggestedFix).toBeNull();
      }
    }
  });

  it('lets a detector-provided explanation take precedence over the LLM explanation', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      okResponse({ 'set-cookie': 'session=abc123' }),
    );
    const llmEnrichImpl: LlmEnrichImpl = vi.fn<LlmEnrichImpl>(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'LLM paraphrase', suggestedFix: 'LLM fix' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await completedScan(svc, scan.id);

    const [target] = completed.targets;
    const cookieFinding = target?.findings.find((f) => f.category === 'cookie-missing-secure');
    expect(cookieFinding?.explanation).toContain('session');
    expect(cookieFinding?.explanation).not.toBe('LLM paraphrase');
    expect(cookieFinding?.suggestedFix).toBe('LLM fix');
  });
});

describe('ScannerService active-mode query-param injection', () => {
  it('records one injection attempt per query parameter on an active-mode target', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/search?q=test&page=1'], {
      mode: 'active',
      confirmAuthorized: true,
    });

    await completedScan(svc, scan.id);

    const target = (await svc.getScan(scan.id))?.targets[0];
    expect(target?.injectionAttempts?.map((a) => a.injectionPoint)).toEqual(['q', 'page']);
  });

  it('records a unique canary marker payload per injection point', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/search?q=test&page=1'], {
      mode: 'active',
      confirmAuthorized: true,
    });

    await completedScan(svc, scan.id);

    const attempts = (await svc.getScan(scan.id))?.targets[0]?.injectionAttempts ?? [];
    const payloads = attempts.map((a) => a.payload);
    for (const payload of payloads) {
      expect(payload).toMatch(/^<script>window\.__colossus_xss_marker='[0-9a-f-]{36}'<\/script>$/);
    }
    // Each attempt gets a fresh marker — no reuse across injection points.
    expect(new Set(payloads).size).toBe(payloads.length);
    // The mutated URL carrying the canary was actually fetched for each point.
    expect(fetchImpl).toHaveBeenCalledWith(
      expect.stringContaining('__colossus_xss_marker'),
      expect.anything(),
    );
  });

  it('records zero injection attempts for an active-mode target with no query parameters', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/'], { mode: 'active', confirmAuthorized: true });

    await completedScan(svc, scan.id);

    const target = (await svc.getScan(scan.id))?.targets[0];
    expect(target?.status).toBe('ok');
    expect(target?.injectionAttempts ?? []).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalledWith(
      expect.stringContaining('__colossus_xss_marker'),
      expect.anything(),
    );
  });
});

describe('ScannerService same-origin link discovery', () => {
  // Discovery reads a body only when the server says it is HTML, so these fixtures
  // set content-type the way a real page would.
  const HTML_HEADERS = { ...FULLY_HARDENED_HEADERS, 'content-type': 'text/html; charset=utf-8' };

  function htmlResponse(html: string): Response {
    return new Response(html, { status: 200, headers: HTML_HEADERS });
  }

  async function runScanToCompletion(fetchImpl: FetchImpl, roots: string[], timeout = SCAN_COMPLETION_TIMEOUT_MS) {
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(roots);

    return vi.waitFor(
      async () => {
        const s = await svc.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
        return s;
      },
      { timeout },
    );
  }

  it('adds a same-origin link found in a target page as a new scan target, tracing it back to the source', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url) =>
      String(url) === 'https://example.com/' ? htmlResponse('<a href="/about">About</a>') : htmlResponse(''),
    );

    const completed = await runScanToCompletion(fetchImpl, ['https://example.com/']);

    expect(completed.targets.map((t) => t.url).sort()).toEqual([
      'https://example.com/',
      'https://example.com/about',
    ]);
    const root = completed.targets.find((t) => t.url === 'https://example.com/');
    const discovered = completed.targets.find((t) => t.url === 'https://example.com/about');
    expect(discovered?.discoveredFrom).toBe(root?.id);
  });

  // The security property the whole feature rests on: an operator attested for the
  // URLs they submitted, so a page they control must not be able to point the
  // scanner at a third party. discovery.test.ts covers the parser; this asserts the
  // boundary survives end-to-end, including that no request is ever made off-origin.
  it('never turns a cross-origin, off-port or off-scheme link into a target', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url) =>
      String(url) === 'https://example.com/'
        ? htmlResponse(
            `<a href="https://evil.example/steal">x</a>
             <a href="https://example.com:8443/admin">x</a>
             <a href="http://example.com/insecure">x</a>
             <form action="https://evil.example/post"></form>
             <a href="/about">ok</a>`,
          )
        : htmlResponse(''),
    );

    const completed = await runScanToCompletion(fetchImpl, ['https://example.com/']);

    expect(completed.targets.map((t) => t.url).sort()).toEqual([
      'https://example.com/',
      'https://example.com/about',
    ]);
    const fetched = vi.mocked(fetchImpl).mock.calls.map(([url]) => new URL(String(url)).origin);
    expect(fetched.every((origin) => origin === 'https://example.com')).toBe(true);
  });

  it('skips a discovered link whose path is disallowed by the target robots.txt', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url) => {
      if (String(url) === 'https://example.com/robots.txt') {
        return new Response('User-agent: *\nDisallow: /admin\n', { status: 200 });
      }
      return String(url) === 'https://example.com/'
        ? htmlResponse('<a href="/admin/settings">Admin</a><a href="/contact">Contact</a>')
        : htmlResponse('');
    });

    const completed = await runScanToCompletion(fetchImpl, ['https://example.com/']);

    expect(completed.targets.map((t) => t.url).sort()).toEqual([
      'https://example.com/',
      'https://example.com/contact',
    ]);
  });

  it('caps discovery at 25 pages per root, counted separately for each submitted root', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url) => {
      const parsed = new URL(String(url));
      if (parsed.pathname !== '/') return htmlResponse('');
      const links = Array.from({ length: 30 }, (_, i) => `<a href="/page${i}">p</a>`).join('');
      return htmlResponse(links);
    });

    const completed = await runScanToCompletion(fetchImpl, ['https://a.example/', 'https://b.example/']);

    for (const host of ['a.example', 'b.example']) {
      const discovered = completed.targets.filter(
        (t) => new URL(t.url).hostname === host && new URL(t.url).pathname !== '/',
      );
      expect(discovered.length).toBe(25);
    }
  });

  it('never crawls deeper than 2 hops from the root, chaining discoveredFrom to the page each link came from', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url) => {
      const nextByPath: Record<string, string> = { '/': '/a', '/a': '/b', '/b': '/c' };
      const next = nextByPath[new URL(String(url)).pathname];
      return htmlResponse(next !== undefined ? `<a href="${next}">next</a>` : '');
    });

    const completed = await runScanToCompletion(fetchImpl, ['https://example.com/']);

    const byUrl = new Map(completed.targets.map((t) => [t.url, t]));
    expect([...byUrl.keys()].sort()).toEqual([
      'https://example.com/',
      'https://example.com/a',
      'https://example.com/b',
    ]);
    // /b was found on /a, not on the root — the field the rootOf/depthOf split
    // could plausibly get wrong.
    expect(byUrl.get('https://example.com/a')?.discoveredFrom).toBe(byUrl.get('https://example.com/')?.id);
    expect(byUrl.get('https://example.com/b')?.discoveredFrom).toBe(byUrl.get('https://example.com/a')?.id);
  });

  it('does not read or parse a body the server did not label as HTML', async () => {
    const fetchImpl: FetchImpl = vi.fn(
      async () =>
        new Response('<a href="/about">About</a>', {
          status: 200,
          headers: { ...FULLY_HARDENED_HEADERS, 'content-type': 'application/octet-stream' },
        }),
    );

    const completed = await runScanToCompletion(fetchImpl, ['https://example.com/']);

    expect(completed.targets.map((t) => t.url)).toEqual(['https://example.com/']);
  });
});

describe('ScannerService active-mode XSS confirmation', () => {
  it('writes an xss finding and records a confirmed outcome when the browser confirms execution', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const xssConfirmImpl = vi.fn(async () => ({ outcome: 'confirmed' as const }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
    });
    const scan = await svc.startScan(['https://example.com/search?q=test'], {
      mode: 'active',
      confirmAuthorized: true,
    });

    await completedScan(svc, scan.id);

    const target = (await svc.getScan(scan.id))?.targets[0];
    const xss = target?.findings.find((f) => f.category === 'xss');
    expect(xss?.severity).toBe('high');
    expect(xss?.confidence).toBe('definitive');
    expect(xss?.injectionPoint).toBe('q');
    expect(xss?.payload).toContain('__colossus_xss_marker');
    expect(target?.injectionAttempts?.map((a) => a.outcome)).toEqual(['confirmed']);
  });

  it('records a not_vulnerable outcome and writes no finding when execution is not confirmed', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const xssConfirmImpl = vi.fn(async () => ({ outcome: 'not_vulnerable' as const }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
    });
    const scan = await svc.startScan(['https://example.com/search?q=test'], {
      mode: 'active',
      confirmAuthorized: true,
    });

    await completedScan(svc, scan.id);

    const target = (await svc.getScan(scan.id))?.targets[0];
    expect(target?.findings.some((f) => f.category === 'xss')).toBe(false);
    expect(target?.injectionAttempts?.map((a) => a.outcome)).toEqual(['not_vulnerable']);
  });

  it('saves the confirmation screenshot to disk and exposes evidencePath on the finding', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const screenshot = Buffer.from('fake-png-bytes-for-evidence');
    const xssConfirmImpl = vi.fn(async () => ({ outcome: 'confirmed' as const, screenshot }));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
    });
    const scan = await svc.startScan(['https://example.com/search?q=test'], {
      mode: 'active',
      confirmAuthorized: true,
    });

    await completedScan(svc, scan.id);

    const xss = (await svc.getScan(scan.id))?.targets[0]?.findings.find((f) => f.category === 'xss');
    expect(xss?.evidencePath).toBe(`data/evidence/${scan.id}/${xss?.id}.png`);
    evidenceDirs.push(`data/evidence/${scan.id}`);
    const written = await readFile(xss!.evidencePath!);
    expect(written.equals(screenshot)).toBe(true);
  });

  it('never runs more browser confirmations at once than the browser-concurrency cap', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    let inFlight = 0;
    let peak = 0;
    const xssConfirmImpl = vi.fn(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight -= 1;
      return { outcome: 'not_vulnerable' as const };
    });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
      browserConcurrency: 2,
    });
    const urls = Array.from({ length: 6 }, (_, i) => `https://example.com/p${i}?q=test`);
    const scan = await svc.startScan(urls, { mode: 'active', confirmAuthorized: true });

    await vi.waitFor(
      async () => {
        const s = await svc.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      { timeout: SCAN_COMPLETION_TIMEOUT_MS },
    );

    expect(xssConfirmImpl).toHaveBeenCalledTimes(6);
    expect(peak).toBeLessThanOrEqual(2);
    expect(peak).toBeGreaterThan(1); // the cap is actually exercised, not accidentally serial
  });
});

// Stands in for the SSRF-guarded content fetch the ssti/sqli/lfi classes use, driving
// each oracle to a confirmation off the URL alone: the injected param carries the
// arithmetic expression (ssti), the lone quote (sqli) or the passwd traversal (lfi),
// while baseline URLs (neutral param values) return none of those signals.
function oracleBody(url: string): string {
  for (const value of new URL(url).searchParams.values()) {
    const product = /(\d+)\*(\d+)/.exec(value);
    if (product !== null) return `<p>total ${Number(product[1]) * Number(product[2])} items</p>`;
    if (value === "'") return 'DB error: You have an error in your SQL syntax; check the manual';
    if (value.includes('etc/passwd')) return 'root:x:0:0:root:/root:/bin/bash';
  }
  return '<p>ok</p>';
}

describe('ScannerService active-mode injection classes', () => {
  async function waitCompleted(svc: ScannerService, scanId: number): Promise<void> {
    await vi.waitFor(
      async () => {
        const s = await svc.getScan(scanId);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      { timeout: SCAN_COMPLETION_TIMEOUT_MS },
    );
  }

  it('confirms xss, ssti, sqli and lfi together on a multi-vuln target', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const xssConfirmImpl = vi.fn(async () => ({ outcome: 'confirmed' as const }));
    const bodyFetchImpl = vi.fn(async (url: string) => oracleBody(url));
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
      bodyFetchImpl,
    });
    const scan = await svc.startScan(['https://example.com/?q=test'], {
      mode: 'active',
      confirmAuthorized: true,
    });
    await waitCompleted(svc, scan.id);

    const target = (await svc.getScan(scan.id))?.targets[0];
    const byCategory = new Map((target?.findings ?? []).map((f) => [f.category, f]));
    for (const category of ['xss', 'ssti', 'sqli', 'lfi']) {
      expect(byCategory.get(category)?.confidence).toBe('definitive');
      expect(byCategory.get(category)?.severity).toBe('high');
      expect(byCategory.get(category)?.injectionPoint).toBe('q');
    }
    expect(byCategory.get('ssti')?.evidenceSnippet).toBeTruthy();
    expect(byCategory.get('sqli')?.evidenceSnippet).toContain('SQL syntax');
    expect(byCategory.get('lfi')?.evidenceSnippet).toContain('root:');
  });

  it('runs the fetch-based classes above the browser cap, not throttled by it', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse(FULLY_HARDENED_HEADERS));
    const xssConfirmImpl = vi.fn(async () => ({ outcome: 'not_vulnerable' as const }));
    let inFlight = 0;
    let peak = 0;
    const bodyFetchImpl = vi.fn(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight -= 1;
      return '<p>ok</p>';
    });
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      xssConfirmImpl,
      bodyFetchImpl,
      browserConcurrency: 2,
    });
    const urls = Array.from({ length: 6 }, (_, i) => `https://example.com/p${i}?q=test`);
    const scan = await svc.startScan(urls, { mode: 'active', confirmAuthorized: true });
    await waitCompleted(svc, scan.id);

    // The fetch classes draw on the wider passive fetch budget, so their confirmations
    // overrun the browser cap of 2 — proof they aren't serialized behind it.
    expect(peak).toBeGreaterThan(2);
  });
});

// Confirmed findings write a PNG under data/evidence/<scan>/; clean up what the
// evidence tests leave behind.
const evidenceDirs: string[] = [];
afterAll(async () => {
  await Promise.all(evidenceDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

// End-to-end through the real Playwright browser (default confirmXss, no mock) against
// a real loopback fixture — the one place the whole active-scan pipeline is exercised
// for real. Everywhere else confirmXss is mocked at its boundary.
describe('ScannerService active-mode XSS confirmation (real browser)', () => {
  const servers: Server[] = [];
  afterAll(async () => {
    await Promise.all(servers.map((srv) => new Promise((r) => srv.close(r))));
  });

  function startFixture(render: (q: string) => string): Promise<string> {
    return new Promise((resolve) => {
      const server = createServer((req, res) => {
        const url = new URL(req.url ?? '/', 'http://localhost');
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(render(url.searchParams.get('q') ?? ''));
      });
      servers.push(server);
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address() as AddressInfo;
        resolve(`http://127.0.0.1:${port}`);
      });
    });
  }

  it('produces a definitive xss finding for a page that reflects the param unescaped', async () => {
    const origin = await startFixture((q) => `<html><body>${q}</body></html>`);
    const svc = new ScannerService(createDb(':memory:'), {
      tlsCheckImpl: okTlsCheckImpl(),
      allowedHosts: ['127.0.0.1'],
    });
    const scan = await svc.startScan([`${origin}/?q=test`], { mode: 'active', confirmAuthorized: true });

    await vi.waitFor(
      async () => {
        const s = await svc.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      { timeout: 30_000 },
    );

    const target = (await svc.getScan(scan.id))?.targets[0];
    const xss = target?.findings.find((f) => f.category === 'xss');
    expect(xss?.confidence).toBe('definitive');
    expect(xss?.evidencePath).toBe(`data/evidence/${scan.id}/${xss?.id}.png`);
    evidenceDirs.push(`data/evidence/${scan.id}`);
    expect(target?.injectionAttempts?.[0]?.outcome).toBe('confirmed');
  }, 40_000);

  it('records not_vulnerable and no finding for a page that escapes the param', async () => {
    const origin = await startFixture(
      (q) => `<html><body>${q.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</body></html>`,
    );
    const svc = new ScannerService(createDb(':memory:'), {
      tlsCheckImpl: okTlsCheckImpl(),
      allowedHosts: ['127.0.0.1'],
    });
    const scan = await svc.startScan([`${origin}/?q=test`], { mode: 'active', confirmAuthorized: true });

    await vi.waitFor(
      async () => {
        const s = await svc.getScan(scan.id);
        if (!s || s.status !== 'completed') throw new Error('not yet completed');
      },
      { timeout: 30_000 },
    );

    const target = (await svc.getScan(scan.id))?.targets[0];
    expect(target?.findings.some((f) => f.category === 'xss')).toBe(false);
    expect(target?.injectionAttempts?.[0]?.outcome).toBe('not_vulnerable');
  }, 40_000);
});

describe('ScannerService body-derived passive checks', () => {
  const HTML_HEADERS = { ...FULLY_HARDENED_HEADERS, 'content-type': 'text/html; charset=utf-8' };

  function htmlResponse(html: string, headers: Record<string, string> = HTML_HEADERS): Response {
    return new Response(html, { status: 200, headers });
  }

  async function scanOne(
    fetchImpl: FetchImpl,
    options: Partial<{ osvCheckImpl: OsvCheckImpl }> = {},
    timeout = SCAN_COMPLETION_TIMEOUT_MS,
  ) {
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      ...options,
    });
    const scan = await svc.startScan(['https://example.com/']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    }, { timeout });
    return completed.targets.find((t) => t.url === 'https://example.com/');
  }

  it('turns each defect in a fetched HTML page into exactly one finding', async () => {
    const page = `<html><head><title>Index of /files</title></head><body>
      <script src="http://cdn.example.com/a.js"></script>
      <form action="http://example.com/login"><input type="password" name="pw"></form>
      </body></html>`;
    const target = await scanOne(vi.fn(async () => htmlResponse(page)));

    expect(target?.findings.map((f) => f.category).sort()).toEqual([
      'directory-listing',
      'insecure-form-action',
      'mixed-content',
      'password-field-autocomplete',
    ]);
  });

  it('routes a generator-tag version into the existing OSV correlation', async () => {
    const osvCheckImpl: OsvCheckImpl = vi.fn(async () => ({ cveId: 'CVE-2024-31210' }));
    const target = await scanOne(
      vi.fn(async () => htmlResponse('<meta name="generator" content="WordPress 6.4.1">')),
      { osvCheckImpl },
    );

    expect(osvCheckImpl).toHaveBeenCalledWith({ software: 'WordPress', version: '6.4.1' });
    expect(target?.findings.find((f) => f.category === 'known-vulnerability')?.cveId).toBe('CVE-2024-31210');
  });

  it('leaves header findings intact when the body cannot be read', async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('<html><form action="http://example.com/x">'));
        controller.error(new Error('socket hang up'));
      },
    });
    const target = await scanOne(vi.fn(async () => new Response(stream, { status: 200, headers: { 'content-type': 'text/html' } })));

    expect(target?.status).toBe('ok');
    expect(target?.findings.map((f) => f.category)).toContain('missing-csp');
  });

  it('runs body checks on the first 2 MB of an oversized body and ignores the rest', async () => {
    // Padding is one long text node, not many elements: the point is to exceed the
    // 2 MB read bound, and a cheap-to-parse body keeps this test off the event loop
    // long enough for the timing-sensitive concurrency test to stay honest.
    const padding = `<div>${'x'.repeat(2_500_000)}</div>`;
    const page = `<form action="http://example.com/login"></form>${padding}<input type="password">`;
    const target = await scanOne(
      vi.fn(async (url) => (String(url).endsWith('/robots.txt') ? new Response('', { status: 404 }) : htmlResponse(page))),
    );

    expect(target?.findings.map((f) => f.category)).toEqual(['insecure-form-action']);
  });
});

describe('ScannerService robots.txt bounds', () => {
  // A robots.txt is an unauthenticated, attacker-controlled body on a target the
  // operator only attested they may scan — it must not be able to stall a worker.
  // No Server/X-Powered-By banner on the page response, so banner extraction falls
  // through to the robots.txt body — the path that actually scans it.
  it('completes a scan whose target serves a hostile multi-megabyte robots.txt', async () => {
    const hostile = 'x'.repeat(3_000_000);
    const fetchImpl: FetchImpl = vi.fn(async (url) =>
      String(url).endsWith('/robots.txt')
        ? new Response(hostile, { status: 200, headers: { 'content-type': 'text/plain' } })
        : okResponse(FULLY_HARDENED_HEADERS),
    );
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/']);

    const completed = await completedScan(svc, scan.id);

    expect(completed.targets[0]?.status).toBe('ok');
  });

  it('still honours Disallow rules that appear within the read bound', async () => {
    const robots = `User-agent: *\nDisallow: /admin\n${'#'.repeat(200)}`;
    const fetchImpl: FetchImpl = vi.fn(async (url) => {
      const href = String(url);
      if (href.endsWith('/robots.txt')) return new Response(robots, { status: 200 });
      const headers = { ...FULLY_HARDENED_HEADERS, 'content-type': 'text/html' };
      if (href === 'https://example.com/')
        return new Response('<a href="/admin/x">a</a><a href="/ok">b</a>', { status: 200, headers });
      return new Response('', { status: 200, headers });
    });
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com/']);

    const completed = await completedScan(svc, scan.id);

    expect(completed.targets.map((t) => t.url).sort()).toEqual(['https://example.com/', 'https://example.com/ok']);
  });
});

describe('ScannerService oracle-confirmed finding storage', () => {
  it('round-trips an ssti finding with a non-null evidence_snippet through getScan', async () => {
    const db = createDb(':memory:');
    const svc = new ScannerService(db);

    const scan = db
      .insert(scans)
      .values({ name: 'x', status: 'completed', urls: ['https://example.com'], createdAt: new Date() })
      .returning({ id: scans.id })
      .get();
    const target = db
      .insert(scanTargets)
      .values({ scanId: scan.id, url: 'https://example.com/?q=1', status: 'ok' })
      .returning({ id: scanTargets.id })
      .get();
    db.insert(findings)
      .values({
        scanTargetId: target.id,
        category: 'ssti',
        severity: 'high',
        confidence: 'definitive',
        evidenceSnippet: '49',
      })
      .run();

    const finding = (await svc.getScan(scan.id))?.targets[0]?.findings.find((f) => f.category === 'ssti');
    expect(finding).toBeDefined();
    expect(finding?.evidenceSnippet).toBe('49');
  });
});

describe('defaultOsvCheck request body', () => {
  it('queries OSV.dev by version and package name without an ecosystem (Generic is not a valid OSV ecosystem)', async () => {
    let capturedBody: unknown;
    const fetchSpy = vi.fn(async (_url: string, init: RequestInit) => {
      capturedBody = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ vulns: [] }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchSpy);

    try {
      await defaultOsvCheck({ software: 'nginx', version: '1.20.1' });
    } finally {
      vi.unstubAllGlobals();
    }

    expect(fetchSpy).toHaveBeenCalledWith('https://api.osv.dev/v1/query', expect.anything());
    expect(capturedBody).toEqual({ version: '1.20.1', package: { name: 'nginx' } });
  });
});
