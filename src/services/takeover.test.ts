import { describe, expect, it } from 'vitest';
import { checkTakeover, type DnsResolverImpl } from './takeover.js';

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
  it('reports a dangling CNAME whose target does not resolve', async () => {
    const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl });

    expect(evidence).toEqual({
      hostname: 'blog.example.com',
      cnameTarget: 'abandoned.s3.amazonaws.com',
      provider: null,
      confidence: 'possible',
    });
  });

  it('reports the dangling target at `possible` confidence, since no fingerprint was matched', async () => {
    const resolverImpl = stubResolver({ cnames: { 'blog.example.com': 'abandoned.s3.amazonaws.com' } });

    const evidence = await checkTakeover('blog.example.com', { resolverImpl });

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

    const evidence = await checkTakeover('blog.example.com', { resolverImpl });

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

    const evidence = await checkTakeover('blog.example.com', { resolverImpl });

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

    const evidence = await checkTakeover('BLOG.example.com.', { resolverImpl });

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
});
