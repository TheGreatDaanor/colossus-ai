import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import { findings } from '../db/schema.js';
import {
  ScannerService,
  ScanValidationError,
  isDisallowedAddress,
  detectHeaderFindings,
  detectTlsFindings,
  extractVersionBanner,
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
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'strict-transport-security': 'max-age=63072000',
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

  it('records a Finding per missing security header and one for an insecure cookie', async () => {
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
    expect(target?.findings).toHaveLength(7);
    expect(target?.findings.map((f) => f.category).sort()).toEqual(
      [
        'insecure-cookie',
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

    // Both targets get the same response — no security headers, plus an insecure
    // session cookie — which yields seven findings each: 2 high (missing CSP,
    // missing HSTS), 2 medium (missing X-Frame-Options, insecure cookie), 3 low
    // (missing X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
    // The summary is therefore exactly double a single target's counts.
    expect(completed.targets).toHaveLength(2);
    expect(completed.findingsBySeverity).toEqual({
      critical: 0,
      high: 4,
      medium: 4,
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

describe('detectHeaderFindings', () => {
  it('flags a response missing all six security headers', () => {
    const result = detectHeaderFindings({});

    expect(result.map((f) => f.category).sort()).toEqual(
      [
        'missing-csp',
        'missing-hsts',
        'missing-permissions-policy',
        'missing-referrer-policy',
        'missing-x-content-type-options',
        'missing-x-frame-options',
      ].sort(),
    );
    for (const finding of result) {
      expect(finding.confidence).toBe('definitive');
    }
  });

  it('does not flag any of the six headers when all are present', () => {
    const result = detectHeaderFindings({
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=63072000',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
    });

    expect(result).toHaveLength(0);
  });

  it('flags missing Referrer-Policy and Permissions-Policy as low severity', () => {
    const result = detectHeaderFindings({});

    expect(result.find((f) => f.category === 'missing-referrer-policy')).toMatchObject({ severity: 'low' });
    expect(result.find((f) => f.category === 'missing-permissions-policy')).toMatchObject({ severity: 'low' });
  });

  it('flags a Set-Cookie header missing Secure, HttpOnly, and SameSite as insecure', () => {
    const result = detectHeaderFindings({ 'set-cookie': 'session=abc123' });

    const cookieFinding = result.find((f) => f.category === 'insecure-cookie');
    expect(cookieFinding).toMatchObject({ severity: 'medium', confidence: 'definitive' });
  });

  it('does not flag a Set-Cookie header that has Secure, HttpOnly, and SameSite set', () => {
    const result = detectHeaderFindings({ 'set-cookie': 'session=abc123; Secure; HttpOnly; SameSite=Strict' });

    expect(result.find((f) => f.category === 'insecure-cookie')).toBeUndefined();
  });

  it('does not flag a cookie when no Set-Cookie header is present', () => {
    const result = detectHeaderFindings({ 'content-security-policy': "default-src 'self'" });

    expect(result.find((f) => f.category === 'insecure-cookie')).toBeUndefined();
  });
});

describe('extractVersionBanner', () => {
  it('extracts a software/version pair from the Server header', () => {
    expect(extractVersionBanner({ server: 'nginx/1.18.0' }, null)).toEqual({
      software: 'nginx',
      version: '1.18.0',
    });
  });

  it('extracts a software/version pair from the X-Powered-By header', () => {
    expect(extractVersionBanner({ 'x-powered-by': 'PHP/7.4.3' }, null)).toEqual({
      software: 'PHP',
      version: '7.4.3',
    });
  });

  it('falls back to a software/version pair found in the robots.txt body', () => {
    expect(extractVersionBanner({}, '# Generated by WordPress/5.4.2')).toEqual({
      software: 'WordPress',
      version: '5.4.2',
    });
  });

  it('prefers a header banner over a robots.txt banner when both are present', () => {
    expect(extractVersionBanner({ server: 'nginx/1.18.0' }, '# Generated by WordPress/5.4.2')).toEqual({
      software: 'nginx',
      version: '1.18.0',
    });
  });

  it('returns null when no banner is found in headers or robots.txt', () => {
    expect(extractVersionBanner({ 'x-test': 'yes' }, 'User-agent: *')).toBeNull();
  });
});

describe('detectTlsFindings', () => {
  const farFutureExpiry = new Date('2099-01-01T00:00:00Z');

  it('flags a TLS version below 1.2 as outdated', () => {
    const result = detectTlsFindings({ version: 'TLSv1', certExpiresAt: farFutureExpiry });

    const finding = result.find((f) => f.category === 'outdated-tls');
    expect(finding).toMatchObject({ severity: 'high', confidence: 'definitive' });
  });

  it('does not flag TLS 1.2 or 1.3 as outdated', () => {
    expect(
      detectTlsFindings({ version: 'TLSv1.2', certExpiresAt: farFutureExpiry }).find(
        (f) => f.category === 'outdated-tls',
      ),
    ).toBeUndefined();
    expect(
      detectTlsFindings({ version: 'TLSv1.3', certExpiresAt: farFutureExpiry }).find(
        (f) => f.category === 'outdated-tls',
      ),
    ).toBeUndefined();
  });

  it('flags a certificate expiring within 30 days as cert-expiring-soon', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const certExpiresAt = new Date('2026-01-10T00:00:00Z');

    const result = detectTlsFindings({ version: 'TLSv1.3', certExpiresAt }, now);

    const finding = result.find((f) => f.category === 'cert-expiring-soon');
    expect(finding).toMatchObject({ severity: 'medium', confidence: 'definitive' });
  });

  it('does not flag a certificate expiring more than 30 days out', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const certExpiresAt = new Date('2026-06-01T00:00:00Z');

    const result = detectTlsFindings({ version: 'TLSv1.3', certExpiresAt }, now);

    expect(result.find((f) => f.category === 'cert-expiring-soon')).toBeUndefined();
  });
});

describe('ScannerService LLM finding enrichment', () => {
  it('populates explanation and suggestedFix on findings from the LLM enrichment call', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map(() => ({ explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
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
      toEnrich.map(() => ({ explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
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
        toEnrich.map(() => ({ explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
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
      okResponse({
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
      }),
    );
    const llmEnrichImpl: LlmEnrichImpl = vi.fn(async (toEnrich) =>
      toEnrich.map(() => ({ explanation: 'plain-english explanation', suggestedFix: 'add the header' })),
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
});
