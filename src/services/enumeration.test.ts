import { describe, expect, it, vi } from 'vitest';
import { EnumerationError, EnumerationService, type CtFetchImpl } from './enumeration.js';

// crt.sh answers with one record per certificate identity; `name_value` holds
// newline-separated names, which is where wildcards and duplicates come from.
// Every test stubs the fetch: none contacts the real crt.sh endpoint.
function ctRecords(...names: string[]): unknown {
  return names.map((name) => ({ name_value: name }));
}

function stubCt(payload: unknown): CtFetchImpl {
  return async () => payload;
}

describe('EnumerationService.enumerate', () => {
  it('returns the hosts named in the CT records, tagged as ct-log', async () => {
    const service = new EnumerationService({ ctFetchImpl: stubCt(ctRecords('blog.example.com', 'api.example.com')) });

    expect(await service.enumerate('example.com')).toEqual([
      { hostname: 'api.example.com', source: 'ct-log' },
      { hostname: 'blog.example.com', source: 'ct-log' },
    ]);
  });

  it('splits the newline-separated names inside one record', async () => {
    const service = new EnumerationService({ ctFetchImpl: stubCt(ctRecords('blog.example.com\napi.example.com')) });

    const hosts = await service.enumerate('example.com');

    expect(hosts.map((h) => h.hostname)).toEqual(['api.example.com', 'blog.example.com']);
  });

  it('deduplicates names that many certificates share', async () => {
    const service = new EnumerationService({
      ctFetchImpl: stubCt(ctRecords('blog.example.com', 'BLOG.example.com.', 'blog.example.com')),
    });

    expect(await service.enumerate('example.com')).toEqual([{ hostname: 'blog.example.com', source: 'ct-log' }]);
  });

  it('reduces a wildcard name to the subtree root', async () => {
    const service = new EnumerationService({ ctFetchImpl: stubCt(ctRecords('*.example.com')) });

    expect(await service.enumerate('example.com')).toEqual([{ hostname: 'example.com', source: 'ct-log' }]);
  });

  it('drops names that are neither the apex nor under it', async () => {
    // One certificate routinely covers several unrelated domains; only the apex
    // being enumerated was authorized, so the rest are not this program's.
    const service = new EnumerationService({
      ctFetchImpl: stubCt(ctRecords('blog.example.com', 'other.example.net', 'notexample.com')),
    });

    expect(await service.enumerate('example.com')).toEqual([{ hostname: 'blog.example.com', source: 'ct-log' }]);
  });

  it('ignores entries that are not shaped like a CT record', async () => {
    const service = new EnumerationService({
      ctFetchImpl: stubCt([{ name_value: 'blog.example.com' }, { other: 1 }, null, 'nonsense']),
    });

    expect(await service.enumerate('example.com')).toEqual([{ hostname: 'blog.example.com', source: 'ct-log' }]);
  });

  it('returns nothing when the response is not a list of records at all', async () => {
    const service = new EnumerationService({ ctFetchImpl: stubCt({ error: 'rate limited' }) });

    expect(await service.enumerate('example.com')).toEqual([]);
  });

  it('caches a result so an on-demand run straight after a scheduled one does not re-query', async () => {
    const ctFetchImpl = vi.fn(async () => ctRecords('blog.example.com'));
    const service = new EnumerationService({ ctFetchImpl });

    await service.enumerate('example.com');
    await service.enumerate('example.com');

    expect(ctFetchImpl).toHaveBeenCalledTimes(1);
  });

  it('re-queries once the cached result has aged out', async () => {
    let now = 0;
    const ctFetchImpl = vi.fn(async () => ctRecords('blog.example.com'));
    const service = new EnumerationService({ ctFetchImpl, cacheTtlMs: 1000, now: () => now });

    await service.enumerate('example.com');
    now = 1001;
    await service.enumerate('example.com');

    expect(ctFetchImpl).toHaveBeenCalledTimes(2);
  });

  it('caches per apex rather than globally', async () => {
    const ctFetchImpl = vi.fn(async () => ctRecords('blog.example.com'));
    const service = new EnumerationService({ ctFetchImpl });

    await service.enumerate('example.com');
    await service.enumerate('example.net');

    expect(ctFetchImpl).toHaveBeenCalledTimes(2);
  });

  it('throws EnumerationError when the CT source fails', async () => {
    const service = new EnumerationService({
      ctFetchImpl: async () => {
        throw new Error('502 Bad Gateway');
      },
    });

    await expect(service.enumerate('example.com')).rejects.toBeInstanceOf(EnumerationError);
  });

  it('does not cache a failure, so the next run tries the source again', async () => {
    const ctFetchImpl = vi.fn(async () => {
      throw new Error('502 Bad Gateway');
    });
    const service = new EnumerationService({ ctFetchImpl });

    await expect(service.enumerate('example.com')).rejects.toBeInstanceOf(EnumerationError);
    await expect(service.enumerate('example.com')).rejects.toBeInstanceOf(EnumerationError);

    expect(ctFetchImpl).toHaveBeenCalledTimes(2);
  });
});
