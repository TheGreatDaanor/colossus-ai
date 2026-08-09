import { describe, expect, it, vi } from 'vitest';
import { createDb } from '../db/client.js';
import {
  ScannerService,
  ScanValidationError,
  isDisallowedAddress,
  detectHeaderFindings,
  type FetchImpl,
} from './scanner.js';

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

function okResponse(body: Record<string, string> = { 'x-test': '1' }): Response {
  return new Response(null, { status: 200, headers: body });
}

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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });
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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });
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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });
    const scan = await svc.startScan(['https://example.com']);

    const completed = await vi.waitFor(async () => {
      const s = await svc.getScan(scan.id);
      if (!s || s.status !== 'completed') throw new Error('not yet completed');
      return s;
    });

    const [target] = completed.targets;
    expect(target?.findings).toHaveLength(5);
    expect(target?.findings.map((f) => f.category).sort()).toEqual(
      [
        'insecure-cookie',
        'missing-csp',
        'missing-hsts',
        'missing-x-content-type-options',
        'missing-x-frame-options',
      ].sort(),
    );
    for (const finding of target?.findings ?? []) {
      expect(finding.confidence).toBe('definitive');
    }
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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });

    const scan = await svc.startScan(['not a url', 'file:///etc/passwd', 'https://good.example.com']);
    const result = await svc.getScan(scan.id);

    const invalidTargets = result?.targets.filter((t) => t.status === 'invalid') ?? [];
    expect(invalidTargets).toHaveLength(2);
    expect(fetchImpl).not.toHaveBeenCalledWith('not a url', expect.anything());
    expect(fetchImpl).not.toHaveBeenCalledWith('file:///etc/passwd', expect.anything());
  });

  it('dedupes exact-string-duplicate URLs into a single target', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => okResponse());
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl });

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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl: vi.fn(async () => okResponse()) });

    const first = await svc.startScan(['https://a.example.com']);
    const second = await svc.startScan(['https://b.example.com']);

    const list = await svc.listScans();

    expect(list.map((s) => s.id)).toEqual([second.id, first.id]);
  });

  it('defaults the scan name to a human-readable timestamp when omitted', async () => {
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl: vi.fn(async () => okResponse()) });
    const scan = await svc.startScan(['https://example.com']);
    expect(scan.name).toMatch(/^Scan \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
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
    const svc = new ScannerService(createDb(':memory:'), { fetchImpl, concurrency: 3 });
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
  it('flags a response missing all four security headers', () => {
    const result = detectHeaderFindings({});

    expect(result.map((f) => f.category).sort()).toEqual(
      ['missing-csp', 'missing-hsts', 'missing-x-content-type-options', 'missing-x-frame-options'].sort(),
    );
    for (const finding of result) {
      expect(finding.confidence).toBe('definitive');
    }
  });

  it('does not flag any of the four headers when all are present', () => {
    const result = detectHeaderFindings({
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=63072000',
    });

    expect(result).toHaveLength(0);
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
