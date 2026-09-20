import { sqliteTable, integer, text, uniqueIndex, type AnySQLiteColumn } from 'drizzle-orm/sqlite-core';

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

// A program is one engagement, not one domain: its in-scope list holds however
// many apexes the engagement covers, and its exclusions are written once across
// all of them. Null host caps mean the mode defaults apply (250 passive, 50
// active), consumed when a program's inventory is scanned.
export const programs = sqliteTable('programs', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  passiveHostCap: integer('passive_host_cap'),
  activeHostCap: integer('active_host_cap'),
  enumerationError: text('enumeration_error'),
  lastEnumeratedAt: integer('last_enumerated_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
});

export type ScopeList = 'in' | 'out';
export type ScopeStatus = 'in_scope' | 'out_of_scope' | 'unscoped';

// `pattern` is an apex, an exact host, or — on the `out` list only — a
// `*.`-prefixed subtree. `confirmedAt` is null until an operator confirms an
// entry that a parser inferred; it is written here but not yet enforced.
export const scopeEntries = sqliteTable('scope_entries', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  programId: integer('program_id')
    .notNull()
    .references(() => programs.id),
  list: text('list').$type<ScopeList>().notNull(),
  pattern: text('pattern').notNull(),
  confirmedAt: integer('confirmed_at', { mode: 'timestamp' }),
});

export type HostSource = 'ct-log' | 'crawl';

// One row per hostname per program: the program's inventory. A host is recorded
// whatever its scope status — an `unscoped` host is kept so the operator can see
// what exists and widen scope deliberately, and is never scanned in the meantime.
export const enumeratedHosts = sqliteTable(
  'enumerated_hosts',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    programId: integer('program_id')
      .notNull()
      .references(() => programs.id),
    hostname: text('hostname').notNull(),
    source: text('source').$type<HostSource>().notNull(),
    scopeStatus: text('scope_status').$type<ScopeStatus>().notNull(),
    // True when the row stands for a subtree rather than a name anyone has seen
    // answer — a `*.` certificate identity, or an apex whose random-nonce label
    // resolves. A wildcard host is shown to the operator and never scanned.
    isWildcard: integer('is_wildcard', { mode: 'boolean' }).notNull().default(false),
    // The URL the host last answered on — HTTPS when it answers on both. Null
    // until it has been probed, and left at its last known value once a host
    // goes dark, so the operator can still see where it used to answer.
    endpointUrl: text('endpoint_url'),
    lastResolvedAt: integer('last_resolved_at', { mode: 'timestamp' }),
    // Consecutive probes that found nothing, reset by any answer. A host that
    // has gone dark keeps its row and its history rather than being dropped:
    // NXDOMAIN on a host that still CNAMEs somewhere is itself a takeover signal.
    failedResolutions: integer('failed_resolutions').notNull().default(0),
    firstSeenAt: integer('first_seen_at', { mode: 'timestamp' }).notNull(),
  },
  (table) => [uniqueIndex('enumerated_hosts_program_hostname').on(table.programId, table.hostname)],
);

// A subdomain-takeover finding, keyed to `enumerated_hosts` rather than
// `scan_targets`: a takeover host frequently does not resolve at all, so it has
// no target row and never runs through the passive/active pipeline. One row per
// host at a time — re-checking a host refreshes its finding in place, and a host
// that has healed has its stale finding removed, so the list stays truthful.
export const takeoverFindings = sqliteTable(
  'takeover_findings',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    enumeratedHostId: integer('enumerated_host_id')
      .notNull()
      .references(() => enumeratedHosts.id),
    // The dangling CNAME target and, when a fingerprint matched it, the provider
    // the operator should reclaim from. `provider` is null for a dangling
    // reference whose target belongs to no known provider.
    cnameTarget: text('cname_target').notNull(),
    provider: text('provider'),
    severity: text('severity').$type<FindingSeverity>().notNull(),
    confidence: text('confidence').$type<FindingConfidence>().notNull(),
    // The operator-facing next step. Names the provider and resource so they can
    // reclaim or remove it themselves — Colossus never claims the resource.
    remediation: text('remediation').notNull(),
    createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  },
  (table) => [uniqueIndex('takeover_findings_host').on(table.enumeratedHostId)],
);
