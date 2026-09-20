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

const app = new Hono();
app.route('/', createScansRoutes(service));
app.route('/', createProgramsRoutes(programsService));
app.route('/', createTakeoverRoutes(takeoverService));
app.route('/', createDashboardRoutes(service));

serve({ fetch: app.fetch, port }, (info) => {
  console.warn(`scanner listening on http://localhost:${info.port}`);
});
