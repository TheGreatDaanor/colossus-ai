import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { findings } from '../db/schema.js';
import {
  ScannerService,
  ScanValidationError,
  isDisallowedAddress,
  type FetchImpl,
  type TlsCheckImpl,
  type OsvCheckImpl,
  type LlmEnrichImpl,
} from './scanner.js';

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

    const [target] = completed.targets;
    expect(target?.status).toBe('ok');
    expect(target?.tlsVersion).toBeNull();
    expect(target?.findings.find((f) => f.category === 'outdated-tls' || f.category === 'cert-expiring-soon')).toBeUndefined();
  });

  it('gives a target on a private/loopback/link-local/metadata IP an invalid status without fetching it', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });

    const scan = await svc.startScan(['http://127.0.0.1', 'http://169.254.169.254']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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
    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });
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
    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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
    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, tlsCheckImpl: okTlsCheckImpl() });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

    const [target] = completed.targets;
    expect(target?.findings.length).toBeGreaterThan(0);
    for (const finding of target?.findings ?? []) {
      expect(finding.explanation).toBe('plain-english explanation');
      expect(finding.suggestedFix).toBe('add the header');
    }
  });

  it('does not call the LLM a second time for an identical finding-set within the same scan', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://a.example.com', 'https://b.example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

    const [target] = completed.targets;
    for (const finding of target?.findings ?? []) {
      expect(finding.explanation).toBe('plain-english explanation');
    }
  });

  it('does not call the LLM when a target produces no findings', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      okResponse(FULLY_HARDENED_HEADERS),
    );
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map((f) => ({ id: f.id, explanation: 'LLM paraphrase', suggestedFix: 'LLM fix' })),
    );
    const svc = new ScannerService(createDb(':memory:'), {
      fetchImpl,
      tlsCheckImpl: okTlsCheckImpl(),
      llmEnrichImpl,
    });

    const scan = await svc.startScan(['https://example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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

    await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
    });

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

  async function runScanToCompletion(fetchImpl: FetchImpl, roots: string[], timeout = 5000) {
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
