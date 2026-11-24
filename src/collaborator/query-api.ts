import { timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import type { HitBuffer } from './hit-buffer.js';

// The internal query API Colossus polls (see `src/services/collaborator-client.ts`
// for the other side of the wire). Every request must carry the shared secret as a
// bearer token; anything else is a 401, so the hit buffer — which names targets that
// are SSRF-vulnerable — is never readable from outside. Bind it to an internal
// interface as well: the secret is the guard, not the only one.
export function createQueryApi(buffer: HitBuffer, secret: string): Hono {
  const expected = Buffer.from(`Bearer ${secret}`);
  const authorized = (header: string | undefined) => {
    if (header === undefined) return false;
    const given = Buffer.from(header);
    // Length first: timingSafeEqual throws on unequal lengths. The length of the
    // secret is not what it protects.
    return given.length === expected.length && timingSafeEqual(given, expected);
  };

  const app = new Hono();
  app.post('/hits', async (c) => {
    if (!authorized(c.req.header('authorization'))) return c.text('unauthorized', 401);
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.text('body must be JSON', 400);
    }
    const tokens = (body as { tokens?: unknown }).tokens;
    if (!Array.isArray(tokens) || !tokens.every((t) => typeof t === 'string')) {
      return c.text('tokens must be an array of strings', 400);
    }
    return c.json({ hits: buffer.query(tokens) });
  });
  return app;
}
