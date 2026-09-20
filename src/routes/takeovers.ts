import { Hono } from 'hono';
import { ProgramValidationError } from '../services/programs.js';
import type { TakeoverFinding, TakeoverService } from '../services/takeover.js';

// The wire keys are snake_case; the service keeps the camelCase domain names, so
// the rename happens here at the response boundary, as it does in programs.ts.
function serializeFinding(finding: TakeoverFinding) {
  const { enumeratedHostId, cnameTarget, createdAt, ...rest } = finding;
  return {
    ...rest,
    enumerated_host_id: enumeratedHostId,
    cname_target: cnameTarget,
    created_at: createdAt,
  };
}

export function createTakeoverRoutes(service: TakeoverService): Hono {
  const app = new Hono();

  // Reads the program's persisted takeover findings. A takeover check runs live
  // DNS, so listing never triggers one — the operator sees whatever the last
  // POST found, and an empty list before any run is a valid answer, not an error.
  app.get('/programs/:id/takeovers', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    try {
      const takeovers = await service.listFindings(id);
      return c.json({ takeovers: takeovers.map(serializeFinding) });
    } catch (err) {
      if (err instanceof ProgramValidationError) return c.json({ error: err.message }, 404);
      throw err;
    }
  });

  // Runs the takeover check across the program's in-scope inventory, persisting
  // and returning what it finds. Separate from the GET because it reaches the
  // network; the operator triggers it deliberately.
  app.post('/programs/:id/takeovers', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    try {
      const takeovers = await service.checkProgram(id);
      return c.json({ takeovers: takeovers.map(serializeFinding) });
    } catch (err) {
      if (err instanceof ProgramValidationError) return c.json({ error: err.message }, 404);
      throw err;
    }
  });

  return app;
}
