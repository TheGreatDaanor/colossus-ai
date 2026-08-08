import { sqliteTable, integer, text } from 'drizzle-orm/sqlite-core';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ScanTargetStatus = 'pending' | 'ok' | 'unreachable' | 'timeout' | 'invalid';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'definitive' | 'possible';

export const scans = sqliteTable('scans', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  status: text('status').$type<ScanStatus>().notNull(),
  urls: text('urls', { mode: 'json' }).$type<string[]>().notNull(),
  userAgent: text('user_agent'),
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
  error: text('error'),
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
});
