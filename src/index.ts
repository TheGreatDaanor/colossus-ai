import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createDb } from './db/client.js';
import { createDashboardRoutes } from './routes/dashboard.js';
import { createProgramsRoutes } from './routes/programs.js';
import { createScansRoutes } from './routes/scans.js';
import { createTakeoverRoutes } from './routes/takeovers.js';
import { EnumerationService } from './services/enumeration.js';
import { ProgramsService } from './services/programs.js';
import { ScannerService } from './services/scanner.js';
import { TakeoverService } from './services/takeover.js';

const port = Number(process.env['PORT'] ?? 3000);
const dbPath = process.env['DB_PATH'] ?? './data/scanner.db';
const defaultUserAgent = process.env['SCANNER_USER_AGENT'] ?? 'colossus-scanner/1.0';

const db = createDb(dbPath);
const programsService = new ProgramsService(db, { enumerationImpl: new EnumerationService({ userAgent: defaultUserAgent }) });
const service = new ScannerService(db, { defaultUserAgent, programsService });
const takeoverService = new TakeoverService(db);

// How stale a program's inventory may get before the scheduler re-enumerates
// it, and how often the scheduler looks for one that has. Cadence is
// configuration, so it lives here rather than in the service: the service is
// handed the cadence and decides which programs it makes due.
const enumerationCadenceMs = Number(process.env['ENUMERATION_CADENCE_MS'] ?? 24 * 60 * 60 * 1000);
const enumerationSweepMs = Number(process.env['ENUMERATION_SWEEP_MS'] ?? 60 * 60 * 1000);

const app = new Hono();
app.route('/', createScansRoutes(service));
app.route('/', createProgramsRoutes(programsService));
app.route('/', createTakeoverRoutes(takeoverService));
app.route('/', createDashboardRoutes(service));

serve({ fetch: app.fetch, port }, (info) => {
  console.warn(`scanner listening on http://localhost:${info.port}`);
});

// A sweep never throws: `enumerateDuePrograms` records a program's failure on
// the program itself, and anything left is logged rather than allowed to take
// the server down with it.
setInterval(() => {
  void programsService
    .enumerateDuePrograms({ cadenceMs: enumerationCadenceMs })
    .catch((err: unknown) => console.warn(`scheduled enumeration sweep failed: ${String(err)}`));
}, enumerationSweepMs);
