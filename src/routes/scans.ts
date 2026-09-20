import { Hono } from 'hono';
import { ScanValidationError, type ScannerService, type StartScanOptions } from '../services/scanner.js';

type StartScanBody = { urls: string[] } & StartScanOptions;

function parseStartScanBody(body: unknown): StartScanBody | null {
  if (typeof body !== 'object' || body === null) return null;
  const { urls, programId, name, userAgent, mode, confirmAuthorized, authorizationNote } = body as Record<string, unknown>;

  if (!Array.isArray(urls) || !urls.every((u): u is string => typeof u === 'string')) return null;
  if (programId !== undefined && !Number.isInteger(programId)) return null;
  if (name !== undefined && typeof name !== 'string') return null;
  if (userAgent !== undefined && typeof userAgent !== 'string') return null;
  if (mode !== undefined && mode !== 'passive' && mode !== 'active') return null;
  if (confirmAuthorized !== undefined && typeof confirmAuthorized !== 'boolean') return null;
  if (authorizationNote !== undefined && typeof authorizationNote !== 'string') return null;

  const parsed: StartScanBody = { urls };
  if (typeof programId === 'number') parsed.programId = programId;
  if (typeof name === 'string') parsed.name = name;
  if (typeof userAgent === 'string') parsed.userAgent = userAgent;
  if (mode === 'passive' || mode === 'active') parsed.mode = mode;
  if (typeof confirmAuthorized === 'boolean') parsed.confirmAuthorized = confirmAuthorized;
  if (typeof authorizationNote === 'string') parsed.authorizationNote = authorizationNote;
  return parsed;
}

export function createScansRoutes(service: ScannerService): Hono {
  const app = new Hono();

  app.post('/scans', async (c) => {
    const rawBody: unknown = await c.req.json().catch(() => null);
    const body = parseStartScanBody(rawBody);
    if (!body) return c.json({ error: 'body must include a `urls` array of strings' }, 400);

    try {
      const { urls, ...options } = body;
      const scan = await service.startScan(urls, options);
      return c.json(scan, 201);
    } catch (err) {
      if (err instanceof ScanValidationError) return c.json({ error: err.message }, 400);
      throw err;
    }
  });

  app.get('/scans', async (c) => {
    const list = await service.listScans();
    return c.json(list);
  });

  app.get('/scans/:id', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.json({ error: 'scan id must be an integer' }, 400);

    const scan = await service.getScan(id);
    if (!scan) return c.json({ error: 'scan not found' }, 404);

    // The issue pins the wire key as snake_case; the service keeps the camelCase
    // domain name, so the rename happens here at the response boundary.
    const { findingsBySeverity, ...rest } = scan;
    return c.json({ ...rest, findings_by_severity: findingsBySeverity });
  });

  return app;
}
