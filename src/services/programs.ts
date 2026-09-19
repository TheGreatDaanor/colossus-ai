import { and, asc, eq, sql } from 'drizzle-orm';
import psl from 'psl';
import type { Db } from '../db/client.js';
import { enumeratedHosts, programs, scopeEntries, type HostSource, type ScopeList, type ScopeStatus } from '../db/schema.js';
import { EnumerationError, type ObservedHost } from './enumeration.js';

export class ProgramValidationError extends Error {}

export type Program = typeof programs.$inferSelect;
export type EnumeratedHost = typeof enumeratedHosts.$inferSelect;
export type ScopeEntry = typeof scopeEntries.$inferSelect;
export type ProgramWithScope = Program & { scopeEntries: ScopeEntry[] };

// The patterns of one program, split by list. Classification needs nothing else,
// which is what keeps it a pure function with no database behind it.
export type Scope = { in: string[]; out: string[] };

export type CreateProgramOptions = {
  url?: string;
  name?: string;
  passiveHostCap?: number;
  activeHostCap?: number;
};

export type AddScopeEntryOptions = { list: ScopeList; pattern: string };

// The one thing this service needs from the enumeration side: given an apex,
// what hosts exist. Injected so scope rules stay testable without a network.
export type EnumerationImpl = { enumerate(apex: string): Promise<ObservedHost[]> };

export type ProgramsServiceOptions = { enumerationImpl?: EnumerationImpl };

export type { ScopeList, ScopeStatus };

const WILDCARD_PREFIX = '*.';

// SQLite binds a limited number of parameters per statement and each row here
// binds five, so a large inventory goes in as several statements inside one
// transaction rather than one statement that would be refused.
const UPSERT_BATCH_SIZE = 100;

// DNS names are case-insensitive and a trailing dot only marks the root, so both
// hosts and patterns are folded to one form before any comparison.
function normaliseHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

function isHostname(candidate: string): boolean {
  return psl.isValid(candidate);
}

// The registrable domain — the apex — computed from the Public Suffix List
// rather than by counting labels, which gets `example.co.uk` wrong. Returns null
// for anything nobody can register: a bare public suffix, or a non-hostname.
export function apexOf(hostname: string): string | null {
  const normalised = normaliseHostname(hostname);
  if (!isHostname(normalised)) return null;
  return psl.get(normalised);
}

function isSubdomainOf(hostname: string, parent: string): boolean {
  return hostname.endsWith(`.${parent}`);
}

// An in-scope pattern is an apex when it is its own registrable domain, and an
// exact host otherwise. That distinction is the whole difference between
// authorizing a domain and authorizing one partner host inside it.
function matchesEntry(hostname: string, pattern: string): boolean {
  if (pattern.startsWith(WILDCARD_PREFIX)) {
    // A `*.`-prefixed subtree covers its own root as well as everything under
    // it: an operator excluding `*.internal.example.com` means the subtree.
    const root = pattern.slice(WILDCARD_PREFIX.length);
    return hostname === root || isSubdomainOf(hostname, root);
  }

  if (hostname === pattern) return true;
  return psl.get(pattern) === pattern && isSubdomainOf(hostname, pattern);
}

function matchesAny(hostname: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesEntry(hostname, normaliseHostname(pattern)));
}

// One ordered rule, first match wins. Out-of-scope is evaluated first so that an
// exclusion is never overridden by a more specific inclusion — an operator who
// writes an exclusion can read it and know it holds.
export function classifyHost(hostname: string, scope: Scope): ScopeStatus {
  const normalised = normaliseHostname(hostname);
  if (!isHostname(normalised)) return 'unscoped';

  if (matchesAny(normalised, scope.out)) return 'out_of_scope';
  if (matchesAny(normalised, scope.in)) return 'in_scope';
  return 'unscoped';
}

function toScope(entries: ScopeEntry[]): Scope {
  return {
    in: entries.filter((e) => e.list === 'in').map((e) => e.pattern),
    out: entries.filter((e) => e.list === 'out').map((e) => e.pattern),
  };
}

function apexFromUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ProgramValidationError(`\`${raw}\` is not a valid URL`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ProgramValidationError('program url must be http or https');
  }

  const apex = apexOf(parsed.hostname);
  if (apex === null) throw new ProgramValidationError(`\`${parsed.hostname}\` has no registrable apex`);
  return apex;
}

// Validated against the grammar the PRD pins: apex or exact host on either list,
// plus `*.`-prefixed subtrees on the out list only. A wildcard inclusion is
// rejected rather than silently widened.
function validatePattern(list: ScopeList, raw: string): string {
  const pattern = normaliseHostname(raw);
  if (pattern === '') throw new ProgramValidationError('scope pattern must not be empty');

  if (pattern.startsWith(WILDCARD_PREFIX)) {
    if (list === 'in') throw new ProgramValidationError('wildcard patterns are only allowed on the out-of-scope list');
    const root = pattern.slice(WILDCARD_PREFIX.length);
    if (!isHostname(root)) throw new ProgramValidationError(`\`${raw}\` is not a valid scope pattern`);
    return pattern;
  }

  if (!isHostname(pattern)) throw new ProgramValidationError(`\`${raw}\` is not a valid scope pattern`);
  return pattern;
}

export class ProgramsService {
  #db: Db;
  #enumerationImpl: EnumerationImpl | null;

  constructor(db: Db, options: ProgramsServiceOptions = {}) {
    this.#db = db;
    this.#enumerationImpl = options.enumerationImpl ?? null;
  }

  async createProgram(options: CreateProgramOptions): Promise<ProgramWithScope> {
    const { url, name, passiveHostCap, activeHostCap } = options;
    if (url === undefined && name === undefined) {
      throw new ProgramValidationError('program requires a `url` or a `name`');
    }

    const apex = url === undefined ? null : apexFromUrl(url);
    const row = this.#db
      .insert(programs)
      .values({
        name: name ?? apex ?? '',
        passiveHostCap: passiveHostCap ?? null,
        activeHostCap: activeHostCap ?? null,
        createdAt: new Date(),
      })
      .returning()
      .get();
    if (!row) throw new Error('failed to insert program');

    // An apex inferred from a URL is left unconfirmed: inferring one widens
    // authorization from a single host to a whole domain, so the operator
    // confirms it before enumeration runs against it.
    if (apex !== null) {
      this.#db.insert(scopeEntries).values({ programId: row.id, list: 'in', pattern: apex, confirmedAt: null }).run();
    }

    return { ...row, scopeEntries: this.#scopeEntriesOf(row.id) };
  }

  async getProgram(id: number): Promise<ProgramWithScope | null> {
    const row = this.#db.select().from(programs).where(eq(programs.id, id)).get();
    if (!row) return null;
    return { ...row, scopeEntries: this.#scopeEntriesOf(row.id) };
  }

  async addScopeEntry(programId: number, options: AddScopeEntryOptions): Promise<ScopeEntry> {
    const { list, pattern: rawPattern } = options;
    this.#requireProgram(programId);
    const pattern = validatePattern(list, rawPattern);

    const existing = this.#db
      .select()
      .from(scopeEntries)
      .where(and(eq(scopeEntries.programId, programId), eq(scopeEntries.list, list), eq(scopeEntries.pattern, pattern)))
      .get();
    if (existing) throw new ProgramValidationError(`\`${pattern}\` is already on the ${list} list`);

    // Typed by an operator rather than inferred by a parser, so it needs no
    // separate confirmation step.
    const row = this.#db
      .insert(scopeEntries)
      .values({ programId, list, pattern, confirmedAt: new Date() })
      .returning()
      .get();
    if (!row) throw new Error('failed to insert scope entry');
    return row;
  }

  async removeScopeEntry(programId: number, entryId: number): Promise<void> {
    this.#requireProgram(programId);

    const removed = this.#db
      .delete(scopeEntries)
      .where(and(eq(scopeEntries.programId, programId), eq(scopeEntries.id, entryId)))
      .returning()
      .get();
    if (!removed) throw new ProgramValidationError(`scope entry ${entryId} not found on program ${programId}`);
  }

  async classify(programId: number, hostname: string): Promise<ScopeStatus> {
    this.#requireProgram(programId);
    return classifyHost(hostname, toScope(this.#scopeEntriesOf(programId)));
  }

  // Records what a source observed, classifying each host as it lands. A host
  // is kept whatever its status: an `unscoped` host is what the operator needs
  // to see in order to widen scope deliberately, and is never scanned meanwhile.
  //
  // The program's passive/active host caps are deliberately not applied here:
  // they bound what a *scan* reaches (issue 037), not what the inventory may
  // know about. Capping the inventory would hide hosts from the operator.
  async recordHosts(programId: number, hosts: ObservedHost[]): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    const scope = toScope(this.#scopeEntriesOf(programId));
    const firstSeenAt = new Date();

    // One CT answer for a busy apex names thousands of hosts, so the rows go in
    // as batched upserts rather than a select-then-write per host. The whole
    // batch is one transaction: a run that fails partway must not leave the
    // operator with an inventory that is neither the old one nor the new one.
    const rows = new Map<
      string,
      { programId: number; hostname: string; source: HostSource; scopeStatus: ScopeStatus; isWildcard: boolean; firstSeenAt: Date }
    >();
    for (const host of hosts) {
      const hostname = normaliseHostname(host.hostname);
      // Last mention of a hostname wins, which matters only for `source`; a
      // host already in the inventory keeps the source it was first seen with.
      rows.set(hostname, {
        programId,
        hostname,
        source: host.source,
        scopeStatus: classifyHost(hostname, scope),
        isWildcard: host.isWildcard === true,
        firstSeenAt,
      });
    }
    if (rows.size === 0) return [];

    const batched = [...rows.values()];
    this.#db.transaction((tx) => {
      for (let i = 0; i < batched.length; i += UPSERT_BATCH_SIZE) {
        tx.insert(enumeratedHosts)
          .values(batched.slice(i, i + UPSERT_BATCH_SIZE))
          // A host already in the inventory keeps its identity and the date it
          // was first seen; its scope status is refreshed because the operator
          // may have changed the lists since, and its wildcard flag because a
          // host first seen behind a `*.` may since have been seen bare.
          .onConflictDoUpdate({
            target: [enumeratedHosts.programId, enumeratedHosts.hostname],
            set: { scopeStatus: sql`excluded.scope_status`, isWildcard: sql`excluded.is_wildcard` },
          })
          .run();
      }
    });

    // Returned in the order the caller observed them, not the order they sit in
    // the table: the caller is reporting on the run it just made.
    const stored = new Map((await this.listHosts(programId)).map((row) => [row.hostname, row]));
    return [...rows.keys()].flatMap((hostname) => {
      const row = stored.get(hostname);
      if (!row) throw new Error(`failed to record enumerated host ${hostname}`);
      return [row];
    });
  }

  async listHosts(programId: number): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    return this.#db
      .select()
      .from(enumeratedHosts)
      .where(eq(enumeratedHosts.programId, programId))
      .orderBy(asc(enumeratedHosts.hostname))
      .all();
  }

  // Enumerates every apex on the in-scope list and records what comes back.
  // A source outage is recorded on the program rather than thrown: the operator
  // still gets the inventory they already had, plus the reason nothing is new.
  async enumerateProgram(programId: number): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    if (this.#enumerationImpl === null) throw new Error('programs service was built without an enumeration source');

    const apexes = this.#apexesOf(programId);
    const observed: ObservedHost[] = [];
    const errors: string[] = [];
    for (const apex of apexes) {
      try {
        observed.push(...(await this.#enumerationImpl.enumerate(apex)));
      } catch (err) {
        if (!(err instanceof EnumerationError)) throw err;
        errors.push(`${apex}: ${err.message}`);
      }
    }

    await this.recordHosts(programId, observed);

    // `lastEnumeratedAt` answers "how fresh is this inventory", so it is stamped
    // only when a source was actually read. A run where every apex failed left
    // the inventory exactly as stale as it was, and must not claim otherwise.
    const readAnySource = errors.length < apexes.length;
    this.#db
      .update(programs)
      .set({
        ...(readAnySource ? { lastEnumeratedAt: new Date() } : {}),
        enumerationError: errors.length === 0 ? null : errors.join('; '),
      })
      .where(eq(programs.id, programId))
      .run();

    return this.listHosts(programId);
  }

  // Only apexes are enumerated: an exact-host entry authorizes that one host,
  // and enumerating its domain would widen the engagement past what was agreed.
  #apexesOf(programId: number): string[] {
    const patterns = this.#scopeEntriesOf(programId)
      .filter((entry) => entry.list === 'in')
      .map((entry) => normaliseHostname(entry.pattern));
    return [...new Set(patterns.filter((pattern) => apexOf(pattern) === pattern))];
  }

  #requireProgram(id: number): Program {
    const row = this.#db.select().from(programs).where(eq(programs.id, id)).get();
    if (!row) throw new ProgramValidationError(`program ${id} not found`);
    return row;
  }

  #scopeEntriesOf(programId: number): ScopeEntry[] {
    return this.#db
      .select()
      .from(scopeEntries)
      .where(eq(scopeEntries.programId, programId))
      .orderBy(asc(scopeEntries.id))
      .all();
  }
}
