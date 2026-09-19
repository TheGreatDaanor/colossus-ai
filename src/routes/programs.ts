import { Hono } from 'hono';
import {
  ProgramValidationError,
  type EnumeratedHost,
  type AddScopeEntryOptions,
  type CreateProgramOptions,
  type ProgramWithScope,
  type ProgramsService,
  type ScopeEntry,
} from '../services/programs.js';

function parseCreateProgramBody(body: unknown): CreateProgramOptions | null {
  if (typeof body !== 'object' || body === null) return null;
  const { url, name, passiveHostCap, activeHostCap } = body as Record<string, unknown>;

  if (url !== undefined && typeof url !== 'string') return null;
  if (name !== undefined && typeof name !== 'string') return null;
  if (passiveHostCap !== undefined && typeof passiveHostCap !== 'number') return null;
  if (activeHostCap !== undefined && typeof activeHostCap !== 'number') return null;

  const parsed: CreateProgramOptions = {};
  if (typeof url === 'string') parsed.url = url;
  if (typeof name === 'string') parsed.name = name;
  if (typeof passiveHostCap === 'number') parsed.passiveHostCap = passiveHostCap;
  if (typeof activeHostCap === 'number') parsed.activeHostCap = activeHostCap;
  return parsed;
}

function parseScopeEntryBody(body: unknown): AddScopeEntryOptions | null {
  if (typeof body !== 'object' || body === null) return null;
  const { list, pattern } = body as Record<string, unknown>;

  if (list !== 'in' && list !== 'out') return null;
  if (typeof pattern !== 'string') return null;
  return { list, pattern };
}

// The wire keys are snake_case; the service keeps the camelCase domain names, so
// the rename happens here at the response boundary, as it does in scans.ts.
function serializeScopeEntry(entry: ScopeEntry) {
  const { programId, confirmedAt, ...rest } = entry;
  return { ...rest, program_id: programId, confirmed_at: confirmedAt };
}

function serializeHost(host: EnumeratedHost) {
  const { programId, scopeStatus, firstSeenAt, ...rest } = host;
  return { ...rest, program_id: programId, scope_status: scopeStatus, first_seen_at: firstSeenAt };
}

function serializeProgram(program: ProgramWithScope) {
  const { scopeEntries, passiveHostCap, activeHostCap, enumerationError, lastEnumeratedAt, createdAt, ...rest } = program;
  return {
    ...rest,
    passive_host_cap: passiveHostCap,
    active_host_cap: activeHostCap,
    enumeration_error: enumerationError,
    last_enumerated_at: lastEnumeratedAt,
    created_at: createdAt,
    scope_entries: scopeEntries.map(serializeScopeEntry),
  };
}

export function createProgramsRoutes(service: ProgramsService): Hono {
  const app = new Hono();

  app.post('/programs', async (c) => {
    const rawBody: unknown = await c.req.json().catch(() => null);
    const body = parseCreateProgramBody(rawBody);
    if (!body) return c.json({ error: 'body must include a `url` or a `name`' }, 400);

    try {
      const program = await service.createProgram(body);
      return c.json(serializeProgram(program), 201);
    } catch (err) {
      if (err instanceof ProgramValidationError) return c.json({ error: err.message }, 400);
      throw err;
    }
  });

  app.get('/programs/:id', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    const program = await service.getProgram(id);
    if (!program) return c.json({ error: 'program not found' }, 404);
    return c.json(serializeProgram(program));
  });

  app.post('/programs/:id/scope', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    const rawBody: unknown = await c.req.json().catch(() => null);
    const body = parseScopeEntryBody(rawBody);
    if (!body) return c.json({ error: 'body must include `list` ("in" or "out") and a `pattern` string' }, 400);

    try {
      const entry = await service.addScopeEntry(id, body);
      return c.json(serializeScopeEntry(entry), 201);
    } catch (err) {
      if (err instanceof ProgramValidationError) return c.json({ error: err.message }, 400);
      throw err;
    }
  });

  app.delete('/programs/:id/scope/:entryId', async (c) => {
    const id = Number(c.req.param('id'));
    const entryId = Number(c.req.param('entryId'));
    if (!Number.isInteger(id) || !Number.isInteger(entryId)) {
      return c.json({ error: 'program id and scope entry id must be integers' }, 400);
    }

    try {
      await service.removeScopeEntry(id, entryId);
      return c.body(null, 204);
    } catch (err) {
      if (err instanceof ProgramValidationError) return c.json({ error: err.message }, 400);
      throw err;
    }
  });

  app.get('/programs/:id/classify', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    const host = c.req.query('host');
    if (host === undefined || host === '') return c.json({ error: 'a `host` query parameter is required' }, 400);

    // Looked up here so that an unknown program is a 404 on a read endpoint,
    // rather than the 400 the service's validation error would otherwise map to.
    const program = await service.getProgram(id);
    if (!program) return c.json({ error: 'program not found' }, 404);

    return c.json({ host, status: await service.classify(id, host) });
  });

  app.post('/programs/:id/enumerate', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    if (!(await service.getProgram(id))) return c.json({ error: 'program not found' }, 404);

    // The service records a source outage on the program rather than throwing,
    // so this is still a 200: the operator gets the inventory plus the reason.
    const hosts = await service.enumerateProgram(id);
    const program = await service.getProgram(id);
    return c.json({ hosts: hosts.map(serializeHost), enumeration_error: program?.enumerationError ?? null });
  });

  app.get('/programs/:id/hosts', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'program id must be an integer' }, 400);

    const program = await service.getProgram(id);
    if (!program) return c.json({ error: 'program not found' }, 404);

    const hosts = await service.listHosts(id);
    return c.json({ hosts: hosts.map(serializeHost), enumeration_error: program.enumerationError });
  });

  return app;
}
