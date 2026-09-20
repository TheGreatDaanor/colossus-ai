import { createServer, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { createDb } from '../db/client.js';
import { ProgramsService, ProgramValidationError } from './programs.js';
import {
  checkTakeover,
  createTakeoverFetch,
  TakeoverService,
  type DnsResolverImpl,
  type TakeoverFetchImpl,
} from './takeover.js';

class DnsError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

// The resolver is stubbed in every test: no test performs live DNS, so the suite
// neither depends on a third party being up nor on a real domain's records.
// `cnames` is the CNAME chain by name; `addresses` is who resolves to an address.
function stubResolver(records: { cnames?: Record<string, string>; addresses?: string[] }): DnsResolverImpl {
  const cnames = records.cnames ?? {};
  const addresses = new Set(records.addresses ?? []);

  return {
    resolveCname: async (hostname) => {
      const target = cnames[hostname];
      if (target === undefined) throw new DnsError('ENODATA');
      return [target];
    },
    resolveAddresses: async (hostname) => {
      if (!addresses.has(hostname)) throw new DnsError('ENOTFOUND');
      return ['203.0.113.10'];
    },
  };
}

describe('checkTakeover', () => {
  // The provider is never contacted in these tests: a stub stands in for the
  // fetch, so the suite makes no outbound request and no resource is claimed.
  function stubFetch(body: string): TakeoverFetchImpl {
    return async () => body;
  }

  const unreachableFetch: TakeoverFetchImpl = async () => {
    throw new Error('connection refused');
  };

  it('reports a dangling CNAME whose target does not resolve', async () => {
    const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

    expect(evidence).toMatchObject({
      hostname: 'blog.example.com',
      cnameTarget: 'abandoned.s3.amazonaws.com',
      confidence: 'possible',
    });
  });

  it('reports the dangling target at `possible` confidence when no provider response confirms it', async () => {
    const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.unknown-host.example' } });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

    expect(evidence?.confidence).toBe('possible');
    expect(evidence?.provider).toBeNull();
  });

  it('returns null for a CNAME whose target resolves', async () => {
    const resolverImpl = stubResolver({
      cnames: { 'blog.example.com': 'live.s3.amazonaws.com' },
      addresses: ['live.s3.amazonaws.com'],
    });

    expect(await checkTakeover('blog.example.com', { resolverImpl })).toBeNull();
  });

  it('returns null for a host with no CNAME at all, because takeover needs a dangling reference', async () => {
    const resolverImpl = stubResolver({ addresses: ['example.com'] });

    expect(await checkTakeover('example.com', { resolverImpl })).toBeNull();
  });

  it('returns null for a host that does not exist and has no CNAME', async () => {
    const resolverImpl = stubResolver({});

    expect(await checkTakeover('gone.example.com', { resolverImpl })).toBeNull();
  });

  it('reports the final target of a multi-hop CNAME chain', async () => {
    const resolverImpl = stubResolver({
      cnames: {
        'blog.example.com': 'cdn.example.net',
        'cdn.example.net': 'abandoned.github.io',
      },
    });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

    expect(evidence?.cnameTarget).toBe('abandoned.github.io');
  });

  it('returns null when a multi-hop chain ends somewhere that resolves', async () => {
    const resolverImpl = stubResolver({
      cnames: {
        'blog.example.com': 'cdn.example.net',
        'cdn.example.net': 'live.github.io',
      },
      addresses: ['live.github.io'],
    });

    expect(await checkTakeover('blog.example.com', { resolverImpl })).toBeNull();
  });

  it('reports a dangling chain even when the host itself still resolves via the chain root', async () => {
    // The queried host answering an address is not evidence of health here: what
    // matters is whether the reference at the end of the chain is claimable.
    const resolverImpl = stubResolver({
      cnames: { 'blog.example.com': 'abandoned.herokuapp.com' },
      addresses: ['blog.example.com'],
    });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

    expect(evidence?.cnameTarget).toBe('abandoned.herokuapp.com');
  });

  it('gives up on a CNAME loop rather than following it forever', async () => {
    const resolverImpl = stubResolver({
      cnames: { 'a.example.com': 'b.example.com', 'b.example.com': 'a.example.com' },
    });

    expect(await checkTakeover('a.example.com', { resolverImpl })).toBeNull();
  });

  it('normalises case and a trailing dot on the hostname and on the resolved target', async () => {
    const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'Abandoned.S3.amazonaws.com.' } });

    const evidence = await checkTakeover('BLOG.example.com.', { resolverImpl, fetchImpl: unreachableFetch });

    expect(evidence?.hostname).toBe('blog.example.com');
    expect(evidence?.cnameTarget).toBe('abandoned.s3.amazonaws.com');
  });

  it('returns null rather than throwing when the resolver fails for an unrelated reason', async () => {
    // A resolver outage is not evidence of a takeover, so the check fails closed:
    // reporting nothing beats reporting a takeover that is not there.
    const resolverImpl: DnsResolverImpl = {
      resolveCname: async () => {
        throw new DnsError('ESERVFAIL');
      },
      resolveAddresses: async () => {
        throw new DnsError('ESERVFAIL');
      },
    };

    expect(await checkTakeover('blog.example.com', { resolverImpl })).toBeNull();
  });

  it('does not treat a resolver failure on the target as a dangling reference', async () => {
    const resolverImpl: DnsResolverImpl = {
      resolveCname: async (hostname) => {
        if (hostname === 'blog.example.com') return ['target.example.net'];
        throw new DnsError('ENODATA');
      },
      resolveAddresses: async () => {
        throw new DnsError('ESERVFAIL');
      },
    };

    expect(await checkTakeover('blog.example.com', { resolverImpl })).toBeNull();
  });

  describe('provider fingerprints', () => {
    it('names the provider matched from the CNAME target', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

      expect(evidence?.provider).toBe('Amazon S3');
    });

    it('upgrades to definitive when the provider response matches an unclaimed fingerprint', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: stubFetch('<html><body>NoSuchBucket</body></html>'),
      });

      expect(evidence?.confidence).toBe('definitive');
      expect(evidence?.provider).toBe('Amazon S3');
    });

    it('stays possible when the provider response does not match the fingerprint', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: stubFetch('<html><body>Hello from a live site</body></html>'),
      });

      expect(evidence?.confidence).toBe('possible');
    });

    it('stays possible when the provider cannot be reached at all', async () => {
      // The usual shape of a dangling S3 reference: nothing resolves, so there is
      // no response to fingerprint. DNS evidence alone is never `definitive`.
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: unreachableFetch });

      expect(evidence?.confidence).toBe('possible');
    });

    it('leaves the provider null and stays possible for a target no fingerprint covers', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.unknown-host.example' } });

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: stubFetch('NoSuchBucket'),
      });

      expect(evidence?.provider).toBeNull();
      expect(evidence?.confidence).toBe('possible');
    });

    it.each([
      ['abandoned.github.io', 'GitHub Pages', "There isn't a GitHub Pages site here."],
      ['abandoned.herokudns.com', 'Heroku', 'No such app'],
      ['abandoned.azurewebsites.net', 'Azure', 'Error 404 - Web app not found.'],
      ['abandoned.fastly.net', 'Fastly', 'Fastly error: unknown domain'],
      ['abandoned.myshopify.com', 'Shopify', 'Sorry, this shop is currently unavailable.'],
    ])('fingerprints %s as %s', async (target, provider, marker) => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': target } });

      const evidence = await checkTakeover('blog.example.com', { resolverImpl, fetchImpl: stubFetch(marker) });

      expect(evidence?.provider).toBe(provider);
      expect(evidence?.confidence).toBe('definitive');
    });

    it('names the provider and the resource in the remediation, and claims nothing', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: stubFetch('NoSuchBucket'),
      });

      expect(evidence?.remediation).toContain('Amazon S3');
      expect(evidence?.remediation).toContain('abandoned.s3.amazonaws.com');
    });

    it('does not attribute a non-S3 AWS service to Amazon S3', async () => {
      // `*.elb.amazonaws.com` is a load balancer, not a bucket. Naming the wrong
      // provider sends the operator to the wrong console to remediate.
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.eu-west-1.elb.amazonaws.com' } });

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: stubFetch('NoSuchBucket'),
      });

      expect(evidence?.provider).toBeNull();
      expect(evidence?.confidence).toBe('possible');
    });

    it('falls back to http when https cannot be reached', async () => {
      // A dangling reference usually has no certificate valid for the hostname,
      // so https fails before the provider's own words are ever seen.
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });
      const seen: string[] = [];

      const evidence = await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: async (url) => {
          seen.push(url);
          if (url.startsWith('https://')) throw new Error('certificate mismatch');
          return 'NoSuchBucket';
        },
      });

      expect(seen).toEqual(['https://blog.example.com/', 'http://blog.example.com/']);
      expect(evidence?.confidence).toBe('definitive');
    });

    it('does not try http once https has answered', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });
      const seen: string[] = [];

      await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: async (url) => {
          seen.push(url);
          return 'a live site';
        },
      });

      expect(seen).toEqual(['https://blog.example.com/']);
    });

    it('requests the hostname itself, not the provider resource', async () => {
      const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });
      const seen: string[] = [];

      await checkTakeover('blog.example.com', {
        resolverImpl,
        fetchImpl: async (url) => {
          seen.push(url);
          return 'NoSuchBucket';
        },
      });

      expect(seen[0]).toBe('https://blog.example.com/');
    });
  });
});

describe('createTakeoverFetch', () => {
  // The one place in this module that does real I/O, so it is exercised against a
  // local server rather than stubbed: the bounds are the point of it.
  async function serve(handler: (res: ServerResponse) => void): Promise<{ url: string; close: () => Promise<void> }> {
    const server = createServer((_req, res) => handler(res));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as AddressInfo;
    return {
      url: `http://127.0.0.1:${address.port}/`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it('gives up on a server that never answers, instead of hanging', async () => {
    const { url, close } = await serve(() => {
      // Never responds: the request is left open until the client gives up.
    });

    try {
      await expect(createTakeoverFetch({ timeoutMs: 100 })(url)).rejects.toThrow();
    } finally {
      await close();
    }
  });

  it('reads only the first bytes of an oversized body', async () => {
    const { url, close } = await serve((res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('x'.repeat(200_000));
    });

    try {
      const body = await createTakeoverFetch({ timeoutMs: 2_000, maxBytes: 1_024 })(url);
      expect(body.length).toBe(1_024);
    } finally {
      await close();
    }
  });
});

describe('TakeoverService', () => {
  // A resolver stub for a whole program: `cnames` is the CNAME by host, and
  // `addresses` is the set of names that resolve to an address. A CNAME target
  // absent from `addresses` is dangling — the takeover case.
  function stubResolver(records: { cnames?: Record<string, string>; addresses?: string[] }): DnsResolverImpl {
    const cnames = records.cnames ?? {};
    const addresses = new Set(records.addresses ?? []);
    return {
      resolveCname: async (hostname) => {
        const target = cnames[hostname];
        if (target === undefined) throw new DnsError('ENODATA');
        return [target];
      },
      resolveAddresses: async (hostname) => {
        if (!addresses.has(hostname)) throw new DnsError('ENOTFOUND');
        return ['203.0.113.10'];
      },
    };
  }

  const unreachableFetch: TakeoverFetchImpl = async () => {
    throw new Error('connection refused');
  };

  // Seeds a program scoped to example.com with the given hosts already in its
  // inventory, and returns both services sharing one database.
  async function buildProgram(hosts: { hostname: string; isWildcard?: boolean }[]) {
    const db = createDb(':memory:');
    const programs = new ProgramsService(db);
    const program = await programs.createProgram({ name: 'Acme', url: 'https://example.com' });
    await programs.recordHosts(
      program.id,
      hosts.map((h) => ({ hostname: h.hostname, source: 'ct-log' as const, ...(h.isWildcard ? { isWildcard: true } : {}) })),
    );
    return { db, programId: program.id, programs };
  }

  it('persists a takeover finding for a dangling in-scope host', async () => {
    const { db, programId } = await buildProgram([{ hostname: 'blog.example.com' }]);
    const service = new TakeoverService(db, {
      resolverImpl: stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } }),
      fetchImpl: unreachableFetch,
    });

    const found = await service.checkProgram(programId);

    expect(found).toEqual([
      expect.objectContaining({
        hostname: 'blog.example.com',
        cnameTarget: 'abandoned.s3.amazonaws.com',
        provider: 'Amazon S3',
        confidence: 'possible',
        severity: 'medium',
        remediation: expect.stringContaining('Colossus has not claimed'),
      }),
    ]);
    expect(await service.listFindings(programId)).toEqual(found);
  });

  it('records a finding for a host that does not resolve to an address at all', async () => {
    // The host has a dangling CNAME but no A record of its own — the common
    // shape of a takeover, and the case a scan_targets-keyed table could not hold.
    const { db, programId } = await buildProgram([{ hostname: 'gone.example.com' }]);
    const service = new TakeoverService(db, {
      resolverImpl: stubResolver({ cnames: { 'gone.example.com': 'orphan.unknown-host.example' } }),
      fetchImpl: unreachableFetch,
    });

    const found = await service.checkProgram(programId);

    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ hostname: 'gone.example.com', provider: null, confidence: 'possible' });
  });

  it('rates a provider-confirmed takeover high severity at definitive confidence', async () => {
    const { db, programId } = await buildProgram([{ hostname: 'shop.example.com' }]);
    const service = new TakeoverService(db, {
      resolverImpl: stubResolver({ cnames: { 'shop.example.com': 'abandoned.s3.amazonaws.com' } }),
      fetchImpl: async () => 'NoSuchBucket',
    });

    const [finding] = await service.checkProgram(programId);

    expect(finding).toMatchObject({ confidence: 'definitive', severity: 'high' });
  });

  it('never checks out-of-scope, unscoped, or wildcard hosts', async () => {
    const { db, programId, programs } = await buildProgram([
      { hostname: 'in.example.com' },
      { hostname: 'wild.example.com', isWildcard: true },
      { hostname: 'other.example.org' }, // unscoped: not under example.com
    ]);
    await programs.addScopeEntry(programId, { list: 'out', pattern: 'excluded.example.com' });
    await programs.recordHosts(programId, [{ hostname: 'excluded.example.com', source: 'ct-log' }]);

    const service = new TakeoverService(db, {
      resolverImpl: stubResolver({
        cnames: {
          'in.example.com': 'a.s3.amazonaws.com',
          'wild.example.com': 'b.s3.amazonaws.com',
          'other.example.org': 'c.s3.amazonaws.com',
          'excluded.example.com': 'd.s3.amazonaws.com',
        },
      }),
      fetchImpl: unreachableFetch,
    });

    const found = await service.checkProgram(programId);

    expect(found.map((f) => f.hostname)).toEqual(['in.example.com']);
  });

  it('refreshes a host in place on re-check rather than duplicating it', async () => {
    const { db, programId } = await buildProgram([{ hostname: 'blog.example.com' }]);
    const service = new TakeoverService(db, {
      resolverImpl: stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } }),
      fetchImpl: unreachableFetch,
    });

    await service.checkProgram(programId);
    const second = await service.checkProgram(programId);

    expect(second).toHaveLength(1);
  });

  it('clears a finding for a host that has since been reclaimed', async () => {
    const { db, programId } = await buildProgram([{ hostname: 'blog.example.com' }]);
    const dangling = new TakeoverService(db, {
      resolverImpl: stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } }),
      fetchImpl: unreachableFetch,
    });
    await dangling.checkProgram(programId);

    // The CNAME target now resolves: the resource was reclaimed, so no takeover.
    const healed = new TakeoverService(db, {
      resolverImpl: stubResolver({
        cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' },
        addresses: ['abandoned.s3.amazonaws.com'],
      }),
      fetchImpl: unreachableFetch,
    });

    expect(await healed.checkProgram(programId)).toEqual([]);
    expect(await healed.listFindings(programId)).toEqual([]);
  });

  it('rejects an unknown program', async () => {
    const db = createDb(':memory:');
    const service = new TakeoverService(db, { fetchImpl: unreachableFetch });
    await expect(service.checkProgram(999)).rejects.toThrow(ProgramValidationError);
  });
});
