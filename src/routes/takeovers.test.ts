import { describe, expect, it } from 'vitest';
import { createDb } from '../db/client.js';
import { ProgramsService } from '../services/programs.js';
import { TakeoverService, type DnsResolverImpl, type TakeoverFetchImpl } from '../services/takeover.js';
import { createTakeoverRoutes } from './takeovers.js';

async function json<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

type TakeoverBody = {
  id: number;
  enumerated_host_id: number;
  hostname: string;
  cname_target: string;
  provider: string | null;
  severity: string;
  confidence: string;
  remediation: string;
  created_at: string;
};
type TakeoversBody = { takeovers: TakeoverBody[] };

class DnsError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function stubResolver(cnames: Record<string, string>): DnsResolverImpl {
  return {
    resolveCname: async (hostname) => {
      const target = cnames[hostname];
      if (target === undefined) throw new DnsError('ENODATA');
      return [target];
    },
    resolveAddresses: async () => {
      throw new DnsError('ENOTFOUND');
    },
  };
}

const unreachableFetch: TakeoverFetchImpl = async () => {
  throw new Error('connection refused');
};

async function buildApp() {
  const db = createDb(':memory:');
  const programs = new ProgramsService(db);
  const program = await programs.createProgram({ name: 'Acme', url: 'https://example.com' });
  await programs.recordHosts(program.id, [
    { hostname: 'blog.example.com', source: 'ct-log' },
    { hostname: 'gone.example.com', source: 'ct-log' },
  ]);
  const takeovers = new TakeoverService(db, {
    resolverImpl: stubResolver({
      'blog.example.com': 'abandoned.s3.amazonaws.com',
      'gone.example.com': 'orphan.unknown-host.example',
    }),
    fetchImpl: unreachableFetch,
  });
  return { app: createTakeoverRoutes(takeovers), programId: program.id };
}

describe('GET /programs/:id/takeovers', () => {
  it('lists persisted takeover findings for a program, including a non-resolving host', async () => {
    const { app, programId } = await buildApp();

    // Run the checks (a real operator POSTs this), then read them back.
    await app.request(`/programs/${programId}/takeovers`, { method: 'POST' });

    const res = await app.request(`/programs/${programId}/takeovers`);
    expect(res.status).toBe(200);

    const body = await json<TakeoversBody>(res);
    expect(body.takeovers).toEqual([
      expect.objectContaining({ hostname: 'blog.example.com', cname_target: 'abandoned.s3.amazonaws.com', provider: 'Amazon S3' }),
      expect.objectContaining({ hostname: 'gone.example.com', provider: null }),
    ]);
  });

  it('returns an empty list before any check has run', async () => {
    const { app, programId } = await buildApp();

    const res = await app.request(`/programs/${programId}/takeovers`);
    expect(res.status).toBe(200);
    expect((await json<TakeoversBody>(res)).takeovers).toEqual([]);
  });

  it('returns 404 for an unknown program', async () => {
    const { app } = await buildApp();
    expect((await app.request('/programs/9999/takeovers')).status).toBe(404);
  });

  it('rejects a non-integer program id', async () => {
    const { app } = await buildApp();
    expect((await app.request('/programs/abc/takeovers')).status).toBe(400);
  });
});
