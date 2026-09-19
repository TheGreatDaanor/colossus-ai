import { sqliteTable, integer, text, type AnySQLiteColumn } from 'drizzle-orm/sqlite-core';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ScanMode = 'passive' | 'active';
export type ScanTargetStatus = 'pending' | 'ok' | 'unreachable' | 'timeout' | 'invalid';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'definitive' | 'possible';

// Oracle-confirmed active-scan categories. Passive/CVE detectors emit many more
// free-form category strings, so this is a documented subset the injection-class
// confirmers annotate against, not an exhaustive enum of the `category` column.
export type FindingCategory = 'xss' | 'ssti' | 'sqli' | 'lfi';

export type XssOutcome = 'confirmed' | 'not_vulnerable' | 'unavailable';

// An active-mode canary injection attempt against one query parameter, recorded per
// target. `outcome` is the browser-confirmation result from 011; `error` carries the
// reason a `not_vulnerable`/`unavailable` attempt could not be confirmed, when known.
export type InjectionAttempt = {
  injectionPoint: string;
  payload: string;
  outcome?: XssOutcome;
  error?: string;
};

export const scans = sqliteTable('scans', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  status: text('status').$type<ScanStatus>().notNull(),
  urls: text('urls', { mode: 'json' }).$type<string[]>().notNull(),
  userAgent: text('user_agent'),
  mode: text('mode').$type<ScanMode>().notNull().default('passive'),
  confirmAuthorized: integer('confirm_authorized', { mode: 'boolean' }),
  authorizationNote: text('authorization_note'),
  error: text('error'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  completedAt: integer('completed_at', { mode: 'timestamp' }),
});

export const scanTargets = sqliteTable('scan_targets', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  scanId: integer('scan_id')
    .notNull()
    .references(() => scans.id),
  url: text('url').notNull(),
  status: text('status').$type<ScanTargetStatus>().notNull(),
  statusCode: integer('status_code'),
  responseHeaders: text('response_headers', { mode: 'json' }).$type<Record<string, string>>(),
  responseTimeMs: integer('response_time_ms'),
  tlsVersion: text('tls_version'),
  tlsCertExpiresAt: integer('tls_cert_expires_at', { mode: 'timestamp' }),
  redirectLocation: text('redirect_location'),
  injectionAttempts: text('injection_attempts', { mode: 'json' }).$type<InjectionAttempt[]>(),
  error: text('error'),
  discoveredFrom: integer('discovered_from').references((): AnySQLiteColumn => scanTargets.id),
});

export const findings = sqliteTable('findings', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  scanTargetId: integer('scan_target_id')
    .notNull()
    .references(() => scanTargets.id),
  category: text('category').notNull(),
  severity: text('severity').$type<FindingSeverity>().notNull(),
  confidence: text('confidence').$type<FindingConfidence>().notNull(),
  cveId: text('cve_id'),
  explanation: text('explanation'),
  suggestedFix: text('suggested_fix'),
  // Set only on browser-confirmed XSS findings (category 'xss'): which query
  // parameter was injected and the canary payload that executed.
  injectionPoint: text('injection_point'),
  payload: text('payload'),
  // Set only on browser-confirmed findings: relative path to the evidence screenshot
  // under data/evidence/<scan_id>/<finding_id>.png. Written once, never deleted.
  evidencePath: text('evidence_path'),
  // Set only on oracle-confirmed non-XSS findings (ssti/sqli/lfi): the response
  // substring that proved the injection. XSS keeps using `evidencePath` (screenshot).
  evidenceSnippet: text('evidence_snippet'),
});
