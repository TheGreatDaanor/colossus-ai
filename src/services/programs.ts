import { and, asc, eq } from 'drizzle-orm';
import psl from 'psl';
import type { Db } from '../db/client.js';
import { programs, scopeEntries, type ScopeList, type ScopeStatus } from '../db/schema.js';

export class ProgramValidationError extends Error {}

export type Program = typeof programs.$inferSelect;
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

export type { ScopeList, ScopeStatus };

const WILDCARD_PREFIX = '*.';

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

  constructor(db: Db) {
    this.#db = db;
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
